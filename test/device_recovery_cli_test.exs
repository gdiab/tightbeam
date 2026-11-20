defmodule Tightbeam.DeviceRecoveryCliTest do
  @moduledoc """
  Stage 1 (stage1-v8) offline ceremonies through the real CLI binary: P4, P5, P5b, P6
  (`tightbeam recover-admin`) and P5c (`tightbeam root-admin`, root, CI only).

  Each test builds an isolated base directory with a file-backed `state.db`, runs
  the release CLI with `TIGHTBEAM_BASE_DIR` pointed at it, and gives it a
  pseudo-terminal with `script`. Nothing here touches a real gateway, a real base
  directory or a real credential.
  """

  use Tightbeam.TestCase, async: false

  alias Tightbeam.{
    DB,
    DeviceLifecycle,
    Devices,
    EventLog,
    Model,
    Native,
    Org,
    PairingAdmission,
    Schema,
    TestDevices
  }

  @moduletag timeout: 600_000
  @cli Path.expand("../cli/target/release/tightbeam", __DIR__)

  setup do
    tmp = Path.join(System.tmp_dir!(), "recovery-#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp)
    on_exit(fn -> File.rm_rf(tmp) end)
    # A persistent database needs an admitted payload, as the gateway's does.
    plan = Tightbeam.GuardRuntimeFixture.prepare!(tmp, "guard_client_e2e_runtime.exs")
    base = plan.base
    File.mkdir_p!(base)
    db = :"recovery_db_#{System.unique_integer([:positive])}"

    # The test's own connection seeds and reads the base while the CLI runs, so it does
    # not take the gateway's base lock (a test-build-only option); the gateway starts
    # raced below are real ones that do.
    start_supervised!(
      {DB,
       path: Path.join(base, "state.db"),
       name: db,
       guard_inputs: [],
       payload_root: plan.payload,
       base_lock: false}
    )

    :ok = Schema.ensure_all(db)
    admission = :"recovery_admission_#{System.unique_integer([:positive])}"
    start_supervised!({PairingAdmission, name: admission})

    george = TestDevices.paired!(db, "george", admin: true, device_id: "iphone")
    ipad = TestDevices.paired!(db, "george", device_id: "ipad")
    _guest = TestDevices.paired!(db, "guest", device_id: "guest-phone")

    Org.create(db, %{
      session_key: Org.personal_session_key("george"),
      display_name: "Main",
      kind: "main",
      is_built_in: true,
      owner_user_id: "george",
      origin: "user:george",
      archetype: "default",
      host: "testhost",
      harness: "claude",
      provider: "anthropic",
      model: Model.new("fable")
    })

    :ok = Org.put_setting(db, "owner-alerts-user", "george")

    call = TestDevices.device_call(george, %{verb: "recovery-enroll", params: %{}})
    %{user_id: "george"} = DeviceLifecycle.enroll(db, call)
    assert_received {:tightbeam_ephemeral, text}
    [secret] = Regex.run(~r/TBR-[0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5}/, text)

    %{
      base: base,
      payload: plan.payload,
      db: db,
      admission: admission,
      george: george,
      ipad: ipad,
      secret: secret
    }
  end

  ## running the CLI

  # Run `args` on a pseudo-terminal, typing `input` after `delay` seconds.
  defp on_tty(ctx, args, input, opts \\ []) do
    delay = Keyword.get(opts, :delay, "0.6")
    prefix = Keyword.get(opts, :prefix, [])
    cwd = Keyword.get(opts, :cwd, ctx.base)
    command = Enum.map_join(prefix ++ [@cli | args], " ", &shell_quote/1)

    linger = Keyword.get(opts, :linger, 2)

    System.cmd("sh", ["-c", tty_pipeline(command, input, delay, linger)],
      cd: cwd,
      env: env(ctx),
      stderr_to_stdout: true
    )
  end

  # `command` on a pseudo-terminal, with `input` typed after `delay` seconds.
  defp tty_pipeline(command, input, delay, linger) do
    script =
      case :os.type() do
        {:unix, :darwin} -> "script -q /dev/null sh -c #{shell_quote(command)}"
        _ -> "script -qec #{shell_quote(command)} /dev/null"
      end

    "(sleep #{delay}; printf '%s\\n' #{shell_quote(input)}; sleep #{linger}) | #{script}"
  end

  defp env(ctx),
    do: [{"TIGHTBEAM_BASE_DIR", ctx.base}, {"TIGHTBEAM_URL", nil}, {"TIGHTBEAM_TOKEN", nil}]

  defp shell_quote(text), do: "'" <> String.replace(text, "'", "'\\''") <> "'"

  defp code_in(output) do
    case Regex.run(~r/TB-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}/, output) do
      [code] -> code
      _ -> nil
    end
  end

  defp lifecycle(db, kind), do: Enum.filter(EventLog.lifecycle_events(db), &(&1.kind == kind))

  defp tokens(db) do
    {:ok, rows} = DB.query(db, "SELECT deviceId, token FROM devices ORDER BY deviceId")
    rows
  end

  defp consumed?(db) do
    {:ok, [[consumed]]} =
      DB.query(db, "SELECT consumedAt FROM recovery_secrets WHERE userId = 'george'")

    not is_nil(consumed)
  end

  ## P4: refusals

  test "P4: the ceremony refuses with the lock held, in a session directory, without a terminal, for an unknown or non-admin user, and for a wrong secret",
       ctx do
    before = tokens(ctx.db)

    # The gateway running (the lock held).
    holder = hold_lock(Path.join(ctx.base, "gateway.lock"))
    {output, status} = on_tty(ctx, ["recover-admin", "--user", "george"], ctx.secret)
    assert status != 0, output
    assert output =~ "base-directory lock is held"
    release_lock(holder)

    # From a directory with a session credential.
    session_dir = Path.join(ctx.base, "session")
    File.mkdir_p!(Path.join(session_dir, "inner"))

    File.write!(
      Path.join(session_dir, ".tightbeam-session"),
      ~s({"url":"http://127.0.0.1:1","token":"x"})
    )

    {output, status} =
      on_tty(ctx, ["recover-admin", "--user", "george"], ctx.secret,
        cwd: Path.join(session_dir, "inner")
      )

    assert status != 0
    assert output =~ "session credential"

    # Standard input from a file, not a terminal.
    secret_file = Path.join(ctx.base, "secret.txt")
    File.write!(secret_file, ctx.secret <> "\n")

    {output, status} =
      System.cmd(
        "sh",
        ["-c", "#{@cli} recover-admin --user george < #{shell_quote(secret_file)}"],
        cd: ctx.base,
        env: env(ctx),
        stderr_to_stdout: true
      )

    assert status != 0
    assert output =~ "needs a terminal"

    # Unknown and non-admin users, and a wrong secret: refused and recorded.
    for {user, input} <- [
          {"nobody", ctx.secret},
          {"guest", ctx.secret},
          {"george", "TBR-AAAAA-BBBBB-CCCCC-DDDDD"}
        ] do
      {output, status} = on_tty(ctx, ["recover-admin", "--user", user], input)
      assert status != 0, output
      assert output =~ "recovery refused"
      refute output =~ ctx.secret
    end

    assert tokens(ctx.db) == before
    refused = lifecycle(ctx.db, "admin_recovery_refused")

    assert Enum.map(refused, &JSON.decode!(&1.detail)["reason"]) == [
             "unknown_user",
             "not_an_admin",
             "wrong_secret"
           ]

    refute Enum.any?(refused, &(&1.detail =~ "TBR-"))
    refute consumed?(ctx.db)
  end

  ## P6 and P5b: the ceremony, resumable and idempotent

  test "P6/P5b: recovery clears tokens, keeps the secret until first sign-in, and can be re-run",
       ctx do
    db = ctx.db

    {first_out, 0} = on_tty(ctx, ["recover-admin", "--user", "george"], ctx.secret)
    first = code_in(first_out)
    assert first, first_out
    refute first_out =~ ctx.secret

    # Every george token is cleared, the guest's is kept; the secret is not consumed.
    assert [["guest-phone", guest_token], ["ipad", nil], ["iphone", nil]] = tokens(db)
    assert is_binary(guest_token)
    refute consumed?(db)
    assert Devices.by_token(db, ctx.george.token) == nil
    assert Devices.by_token(db, ctx.ipad.token) == nil

    [recovered] = lifecycle(db, "admin_recovered")
    detail = JSON.decode!(recovered.detail)
    assert detail["clearedDeviceIds"] == ["ipad", "iphone"]
    assert detail["codeId"] =~ ~r/\Apc_[0-9a-f]{16}\z/
    assert is_binary(detail["account"])
    refute recovered.detail =~ first

    # The output was lost: run it again with the same secret; the first code is void.
    {second_out, 0} = on_tty(ctx, ["recover-admin", "--user", "george"], ctx.secret)
    second = code_in(second_out)
    assert second && second != first

    assert {:refused, "pairing_code_invalid", _} =
             TestDevices.coded_pair(db, "new-iphone", "iPhone", first, ctx.admission)

    # Gateway start: one alert and one Main wake per recovery recorded while stopped.
    :ok = DeviceLifecycle.observe_at_boot(db, "/nonexistent/tightbeam-test/pairing-unfreeze")
    {:ok, alerts} = DB.query(db, "SELECT body FROM owner_alerts WHERE kind = 'admin-recovered'")
    assert length(alerts) == 2
    assert Enum.all?(alerts, fn [body] -> body =~ "Admin devices of george were recovered at" end)

    # The latest code pairs within 60 minutes; the first sign-in consumes the secret.
    assert {:paired, %{token: token, user_id: "george"}} =
             TestDevices.coded_pair(db, "new-iphone", "iPhone", second, ctx.admission)

    refute consumed?(db)
    assert :ok = DeviceLifecycle.sign_in(db, token)
    assert consumed?(db)
    assert [_] = lifecycle(db, "recovery_secret_consumed")

    # A later ceremony with the consumed secret is refused.
    {output, status} = on_tty(ctx, ["recover-admin", "--user", "george"], ctx.secret)
    assert status != 0
    assert output =~ "secret_consumed"
  end

  test "P6: a recovery code older than 60 minutes no longer pairs", ctx do
    {out, 0} = on_tty(ctx, ["recover-admin", "--user", "george"], ctx.secret)
    code = code_in(out)

    {:ok, _} =
      DB.query(ctx.db, "UPDATE pairing_codes SET expiresAt = issuedAt + 1 WHERE recovery = 1")

    assert {:refused, "pairing_code_invalid", _} =
             TestDevices.coded_pair(ctx.db, "late", "Late", code, ctx.admission)
  end

  test "P5b: a ceremony killed at any point leaves a usable path while the secret is unconsumed",
       ctx do
    for delay_ms <- [0, 50, 150, 300, 600, 1_200] do
      script =
        tty_pipeline("#{@cli} recover-admin --user george", ctx.secret, "0.2", 5)

      port =
        Port.open({:spawn_executable, "/bin/sh"}, [
          :binary,
          :exit_status,
          args: ["-c", script],
          cd: ctx.base,
          env:
            Enum.map(env(ctx), fn {k, v} ->
              {String.to_charlist(k), if(v, do: String.to_charlist(v), else: false)}
            end)
        ])

      Process.sleep(delay_ms)
      {:os_pid, pid} = Port.info(port, :os_pid)
      System.cmd("pkill", ["-KILL", "-P", Integer.to_string(pid)])
      System.cmd("kill", ["-KILL", Integer.to_string(pid)])
      flush_port(port)

      # Atomic: either the whole recovery committed with its event, or nothing did.
      recovered = length(lifecycle(ctx.db, "admin_recovered"))

      cleared =
        Enum.all?(tokens(ctx.db), fn [id, token] -> id == "guest-phone" or is_nil(token) end)

      assert recovered == 0 or cleared
      refute consumed?(ctx.db)
    end

    # A complete run afterwards still succeeds with the same secret.
    {out, 0} = on_tty(ctx, ["recover-admin", "--user", "george"], ctx.secret)
    code = code_in(out)
    assert {:paired, _} = TestDevices.coded_pair(ctx.db, "after", "After", code, ctx.admission)
  end

  # The base-directory lock held by its own process, as the gateway holds it, and
  # released when that process exits.
  defp hold_lock(path) do
    case try_hold_lock(path) do
      {:locked, holder} -> holder
      :refused -> flunk("the base-directory lock is unexpectedly held")
    end
  end

  defp try_hold_lock(path) do
    parent = self()

    holder =
      spawn(fn ->
        result =
          try do
            {:locked, Native.base_lock(path)}
          rescue
            ErlangError -> :refused
          end

        send(parent, {:lock_result, self(), elem_or_atom(result)})

        receive do
          :release -> result
        end
      end)

    receive do
      {:lock_result, ^holder, :locked} -> {:locked, holder}
      {:lock_result, ^holder, :refused} -> :refused
    end
  end

  defp elem_or_atom({:locked, _}), do: :locked
  defp elem_or_atom(:refused), do: :refused

  defp release_lock(holder) do
    ref = Process.monitor(holder)
    send(holder, :release)

    receive do
      {:DOWN, ^ref, :process, _, _} -> :ok
    end
  end

  defp flush_port(port) do
    receive do
      {^port, {:exit_status, _}} -> :ok
      {^port, _} -> flush_port(port)
    after
      3_000 -> :ok
    end
  end

  ## P5: the lock decides between a gateway start and the ceremony

  # A real gateway start on `base`: the production database owner, with admission and
  # the base lock, unlinked so a refusal is a return value.
  defp start_gateway_db(ctx, base \\ nil) do
    GenServer.start(DB,
      path: Path.join(base || ctx.base, "state.db"),
      name: nil,
      guard_inputs: [],
      payload_root: ctx.payload
    )
  end

  test "P5: across 200 races, exactly one of a real gateway start and the ceremony proceeds",
       ctx do
    ceremony = fn ->
      on_tty(ctx, ["recover-admin", "--user", "george"], "TBR-AAAAA-BBBBB-CCCCC-DDDDD",
        delay: "0.15",
        linger: "0.4"
      )
    end

    outcomes =
      for n <- 1..200 do
        # The gateway's start is the production database owner, which admits the base
        # and then takes the lock before it opens state.db for writing. Even rounds
        # start the ceremony first, odd rounds the gateway, each at a varying offset.
        {gateway, {output, _status}} =
          if rem(n, 2) == 0 do
            task = Task.async(ceremony)
            Process.sleep(rem(n * 7, 40))
            gateway = start_gateway_db(ctx)
            {gateway, Task.await(task, 30_000)}
          else
            task = Task.async(fn -> start_gateway_db(ctx) end)
            Process.sleep(rem(n * 13, 200))
            result = ceremony.()
            {Task.await(task, 30_000), result}
          end

        ceremony = if output =~ "base-directory lock is held", do: :refused, else: :proceeded

        outcome =
          case gateway do
            {:ok, pid} ->
              GenServer.stop(pid)
              :started

            {:error, {:base_dir_locked, _}} ->
              :refused
          end

        {outcome, ceremony}
      end

    for outcome <- outcomes do
      assert outcome in [{:started, :refused}, {:refused, :proceeded}], inspect(outcome)
    end

    assert Enum.any?(outcomes, &match?({:started, _}, &1))
    assert Enum.any?(outcomes, &match?({:refused, _}, &1))
  end

  test "S1.2: a real gateway start takes the lock before opening state.db, and a second instance refuses",
       ctx do
    # A fresh base: with a ceremony holding its lock, the start refuses before it
    # creates or opens state.db at all.
    fresh = Path.join(Path.dirname(ctx.base), "fresh-#{System.unique_integer([:positive])}")
    File.mkdir_p!(fresh)
    holder = hold_lock(Path.join(fresh, "gateway.lock"))

    assert {:error, {:base_dir_locked, _}} = start_gateway_db(ctx, fresh)
    refute File.exists?(Path.join(fresh, "state.db"))
    release_lock(holder)

    # Released, the same base starts, and while it serves a second instance and the
    # ceremony both refuse.
    {:ok, first} = start_gateway_db(ctx, fresh)
    assert File.exists?(Path.join(fresh, "state.db"))
    # As the first gateway's boot does, so a second start's admission reads a stamp.
    :ok = Schema.ensure_all(first)
    assert {:error, {:base_dir_locked, _}} = start_gateway_db(ctx, fresh)

    {output, _status} =
      on_tty(%{ctx | base: fresh}, ["recover-admin", "--user", "george"], ctx.secret)

    assert output =~ "base-directory lock is held"

    # Stopping the owner releases the lock with it.
    GenServer.stop(first)
    {:ok, again} = start_gateway_db(ctx, fresh)
    GenServer.stop(again)
  end

  ## B3: the secret prompt never leaves the terminal with echo off

  # Run recover-admin on a pseudo-terminal, send `signal` to it while it waits at the
  # secret prompt (echo off), then report the terminal's echo setting afterwards.
  defp echo_after_signal(ctx, signal) do
    pidfile = Path.join(ctx.base, "prompt-#{System.unique_integer([:positive])}.pid")

    inner =
      "echo $$ > #{shell_quote(pidfile)}; exec #{shell_quote(@cli)} recover-admin --user george"

    outer = "sh -c #{shell_quote(inner)}; stty -a"

    script =
      case :os.type() do
        {:unix, :darwin} -> "script -q /dev/null sh -c #{shell_quote(outer)}"
        _ -> "script -qec #{shell_quote(outer)} /dev/null"
      end

    task =
      Task.async(fn ->
        System.cmd("sh", ["-c", "(sleep 5) | #{script}"],
          cd: ctx.base,
          env: env(ctx),
          stderr_to_stdout: true
        )
      end)

    pid = await_pidfile(pidfile, 50)
    Process.sleep(1_000)
    {_, 0} = System.cmd("kill", ["-#{signal}", pid])
    {output, _status} = Task.await(task, 30_000)
    assert output =~ "Recovery secret for george:", output

    [sign] = Regex.run(~r/(?:^|\s)(-?)echo(?=\s|$)/m, output, capture: :all_but_first)
    if sign == "-", do: :off, else: :on
  end

  defp await_pidfile(path, tries) do
    case File.read(path) do
      {:ok, pid} when pid != "" ->
        String.trim(pid)

      _ when tries > 0 ->
        Process.sleep(100)
        await_pidfile(path, tries - 1)

      _ ->
        flunk("the ceremony never started")
    end
  end

  test "B3: an interrupt, a termination or a hangup at the secret prompt restores terminal echo",
       ctx do
    for signal <- ~w(INT TERM HUP), do: assert(echo_after_signal(ctx, signal) == :on, signal)

    # Control: SIGKILL runs no handler, and the probe sees echo left off.
    assert echo_after_signal(ctx, "KILL") == :off
  end

  ## P5c: the root-shell path (CI runners only, where passwordless sudo exists)

  @root_capable System.get_env("CI") == "true" and
                  match?({_, 0}, System.cmd("sudo", ["-n", "true"], stderr_to_stdout: true))
  @tag if(@root_capable, do: [], else: [skip: "needs passwordless sudo on a CI runner"])
  test "P5c: root-admin needs root, a terminal, no session context and the lock; it records, alerts and writes as the owner",
       ctx do
    db = ctx.db
    sudo = ["sudo", "-n", "env", "TIGHTBEAM_BASE_DIR=#{ctx.base}"]

    # Not root: refused.
    {output, status} = on_tty(ctx, ["root-admin", "pairing-code", "--user", "george"], "")
    assert status != 0
    assert output =~ "needs root"

    # Root with the gateway running (the lock held): refused.
    holder = hold_lock(Path.join(ctx.base, "gateway.lock"))

    {output, status} =
      on_tty(ctx, ["root-admin", "pairing-code", "--user", "george"], "", prefix: sudo)

    assert status != 0, output
    assert output =~ "lock is held"
    release_lock(holder)

    # Root from a directory holding a session credential: refused.
    session_dir = Path.join(ctx.base, "session")
    File.mkdir_p!(session_dir)

    File.write!(
      Path.join(session_dir, ".tightbeam-session"),
      ~s({"url":"http://127.0.0.1:1","token":"x"})
    )

    {output, status} =
      on_tty(ctx, ["root-admin", "pairing-code", "--user", "george"], "",
        prefix: sudo,
        cwd: session_dir
      )

    assert status != 0
    assert output =~ "session credential"

    # Root with no controlling terminal: refused.
    {output, status} =
      System.cmd(
        "sudo",
        [
          "-n",
          "env",
          "TIGHTBEAM_BASE_DIR=#{ctx.base}",
          @cli,
          "root-admin",
          "pairing-code",
          "--user",
          "george"
        ],
        cd: ctx.base,
        stderr_to_stdout: true
      )

    assert status != 0
    assert output =~ "terminal"
    assert {:ok, [[0]]} = DB.query(db, "SELECT COUNT(*) FROM gateway_host_actions")

    # Properly: a code and a secret, shown once on the terminal.
    {code_out, 0} =
      on_tty(ctx, ["root-admin", "pairing-code", "--user", "george"], "", prefix: sudo)

    code = code_in(code_out)
    assert code, code_out

    {secret_out, 0} =
      on_tty(ctx, ["root-admin", "recovery-enroll", "--user", "george"], "", prefix: sudo)

    [new_secret] = Regex.run(~r/TBR-[0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5}/, secret_out)

    actions = lifecycle(db, "root_admin_action")

    assert Enum.map(actions, &JSON.decode!(&1.detail)["action"]) == [
             "pairing-code",
             "recovery-enroll"
           ]

    for action <- actions do
      detail = JSON.decode!(action.detail)
      assert detail["userId"] == "george"
      assert detail["account"] == System.get_env("USER")
      assert detail["tty"] =~ "/dev/"
    end

    assert JSON.decode!(hd(actions).detail)["codeId"] =~ ~r/\Apc_/

    # state.db and its journal files still belong to the database's owner.
    owner = File.stat!(Path.join(ctx.base, "state.db")).uid

    for file <-
          Path.wildcard(Path.join(ctx.base, "state.db*")) ++ [Path.join(ctx.base, "gateway.lock")] do
      assert File.stat!(file).uid == owner, file
    end

    # No secret or code appears in any record.
    for table <- ~w(lifecycle_events gateway_host_actions events messages) do
      {:ok, rows} = DB.query(db, "SELECT * FROM #{table}")
      text = inspect(rows, limit: :infinity, printable_limit: :infinity)
      refute text =~ code
      refute text =~ new_secret
    end

    # On start: one alert and one Main wake per action.
    :ok = DeviceLifecycle.observe_at_boot(db, "/nonexistent/tightbeam-test/pairing-unfreeze")

    {:ok, [[2]]} =
      DB.query(
        db,
        "SELECT COUNT(*) FROM owner_alerts WHERE kind IN ('root-pairing-code', 'root-recovery-enroll')"
      )

    {:ok, wakes} = DB.query(db, "SELECT prompt FROM wakes WHERE class = 'blocker'")
    assert length(wakes) == 2

    assert Enum.any?(wakes, fn [prompt] ->
             prompt =~ "A root shell on the gateway host issued a pairing code for george"
           end)

    # The code pairs a device; the new secret enables recover-admin.
    assert {:paired, _} = TestDevices.coded_pair(db, "root-paired", "Duo", code, ctx.admission)
    {out, 0} = on_tty(ctx, ["recover-admin", "--user", "george"], new_secret)
    assert code_in(out)
  end
end
