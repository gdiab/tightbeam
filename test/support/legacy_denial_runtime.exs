# Stage 1 P15 (stage1-v12 S5.1): one gateway database life on a file-backed base, run as
# its own OS process by `device_lifecycle_user_creation_test.exs`. It starts the real
# database owner (admission and the base lock), then:
#
#   migrate-stalled            runs the boot schema, whose stage 1 migration stalls inside
#                              its own transaction at the third denial write: a temporary
#                              trigger on this connection runs an unbounded computation
#                              over a temporary table inside that INSERT, so the
#                              transaction can neither commit nor end. It prints
#                              `denial <n> <device>` as each denial write starts, and is
#                              killed there by the test. Temporary objects take no lock
#                              another connection could hold, so every earlier transaction
#                              proceeds (an attached database's lock would be reserved by
#                              each BEGIN IMMEDIATE and stall the first one).
#   migrate                    runs the boot schema once and stops.
#   boot                       runs the gateway's boot schema and boot observation, as a
#                              gateway restart does, and stops.
#
# Its first line is `pid <os pid>`, so the test can SIGKILL this BEAM (not a wrapper)
# while the stall holds it.

[payload, base, mode | rest] = System.argv()

# The test's Port owns this BEAM's lifetime: when the Port closes (the test finished,
# failed or timed out), standard input reaches EOF and this BEAM halts at once, even
# while its migration is stalled.
spawn(fn ->
  _ = IO.read(:stdio, :eof)
  :erlang.halt(1, flush: false)
end)

true = Path.expand(payload) == Path.expand(Application.app_dir(:tightbeam))
{:ok, _} = Application.ensure_all_started(:exqlite)
{:ok, _} = Application.ensure_all_started(:crypto)
Application.put_env(:tightbeam, :autostart, false)
Application.put_env(:tightbeam, :base_dir, base)

alias Tightbeam.{DB, DeviceLifecycle, Schema}

# The boot schema logs thousands of info lines; keep the output to what the test reads.
Logger.configure(level: :warning)

IO.puts("pid #{System.pid()}")

{:ok, db} =
  DB.start_link(
    path: Path.join(base, "state.db"),
    name: nil,
    guard_inputs: [],
    payload_root: payload
  )

denial = "legacy_pending_device_denied"

case {mode, rest} do
  {"migrate-stalled", []} ->
    # Temporary objects live on one connection: every statement here must reach the
    # writer, which runs the migration (a leading SELECT or WITH goes to a reader).
    {:ok, _} = DB.query(db, "CREATE TEMP TABLE p15_spin (x INTEGER)")

    {:ok, _} =
      DB.query(db, """
      INSERT INTO temp.p15_spin
      WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < 1000)
      SELECT x FROM n
      """)

    # 1000^4 rows: far longer than the test waits before its SIGKILL.
    {:ok, _} =
      DB.query(db, """
      CREATE TEMP TRIGGER p15_stall AFTER INSERT ON main.lifecycle_events
      WHEN NEW.kind = '#{denial}'
        AND (SELECT COUNT(*) FROM main.lifecycle_events WHERE kind = '#{denial}') >= 3
      BEGIN
        SELECT COUNT(*) FROM temp.p15_spin a, temp.p15_spin b, temp.p15_spin c, temp.p15_spin d;
      END
      """)

    # Code loads lazily here: a pattern set before EventLog is loaded matches nothing and
    # is not applied when it loads, so load it first and require the one match.
    Code.ensure_loaded!(Tightbeam.EventLog)
    1 = :erlang.trace_pattern({Tightbeam.EventLog, :lifecycle_in_txn, 4}, true, [:global])
    :erlang.trace(:all, true, [:call, {:tracer, self()}])

    spawn(fn ->
      Schema.ensure_all(db)
      IO.puts("migrate-stalled: the migration returned")
    end)

    watch = fn watch, count ->
      receive do
        {:trace, _pid, :call, {Tightbeam.EventLog, :lifecycle_in_txn, [_txn, ^denial, id, _]}} ->
          IO.puts("denial #{count + 1} #{id}")
          watch.(watch, count + 1)

        _other ->
          watch.(watch, count)
      end
    end

    watch.(watch, 0)

  {"migrate", []} ->
    :ok = Schema.ensure_all(db)
    GenServer.stop(db)
    IO.puts("migrate: ok")

  {"boot", []} ->
    :ok = Schema.ensure_all(db)
    :ok = DeviceLifecycle.observe_at_boot(db, "/nonexistent/tightbeam-p15/pairing-unfreeze")
    GenServer.stop(db)
    IO.puts("boot: ok")
end
