# Stage 1 P15 (stage1-v12 S5.1): one gateway database life on a file-backed base, run as
# its own OS process by `device_lifecycle_user_creation_test.exs`. It starts the real
# database owner (admission and the base lock), then:
#
#   migrate-stalled <lock.db>  runs the boot schema, whose stage 1 migration stalls inside
#                              its own transaction at the third denial write: a temporary
#                              trigger on this connection writes to <lock.db>, whose write
#                              lock the test holds. It prints `denial <n> <device>` as each
#                              denial write starts, and is killed there by the test.
#   migrate                    runs the boot schema once and stops.
#   boot                       runs the gateway's boot schema and boot observation, as a
#                              gateway restart does, and stops.
#
# Its first line is `pid <os pid>`, so the test kills this BEAM itself.

[payload, base, mode | rest] = System.argv()
true = Path.expand(payload) == Path.expand(Application.app_dir(:tightbeam))
{:ok, _} = Application.ensure_all_started(:exqlite)
{:ok, _} = Application.ensure_all_started(:crypto)
Application.put_env(:tightbeam, :autostart, false)
Application.put_env(:tightbeam, :base_dir, base)

alias Tightbeam.{DB, DeviceLifecycle, Schema}

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
  {"migrate-stalled", [lock_db]} ->
    {:ok, _} = DB.query(db, "PRAGMA busy_timeout = 600000")
    {:ok, _} = DB.query(db, "ATTACH DATABASE ?1 AS lockdb", [lock_db])

    {:ok, _} =
      DB.query(db, """
      CREATE TEMP TRIGGER p15_stall AFTER INSERT ON main.lifecycle_events
      WHEN NEW.kind = '#{denial}'
        AND (SELECT COUNT(*) FROM main.lifecycle_events WHERE kind = '#{denial}') >= 3
      BEGIN INSERT INTO lockdb.hold VALUES (1); END
      """)

    :erlang.trace_pattern({Tightbeam.EventLog, :lifecycle_in_txn, 4}, true, [:global])
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
