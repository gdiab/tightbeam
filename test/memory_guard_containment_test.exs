defmodule Tightbeam.MemoryGuardContainmentTest do
  # Memory limits v1.4 §8 T1 (enforced), T2 (watched) and T15 (adapter end),
  # with real processes and a real runaway.
  #
  # Runs only where its environment has a finite memory limit of its own (the
  # CI step `memory containment` sets one up and exports
  # TIGHTBEAM_MEMORY_CONTAINMENT=1); it refuses otherwise, so a failure of
  # Tightbeam's limits can only end the test environment. Never on Sirius.
  #
  # The chain under test: a real `Acp.Adapter` and `Acp.Conn`, the adapter
  # process started through `harness-exec` (joining its unit in enforced mode),
  # a fake ACP agent that starts one real session process per session through
  # `CLAUDE_CODE_EXECUTABLE` with `--session-id`/`--resume` as claude-agent-acp
  # 0.81.0 does (A:6208, 6320; AS2), the real launch step, and a session process
  # whose tool, two levels down, allocates 100 MiB every 100 ms without bound.
  # When a session process dies under a pending prompt the agent answers with
  # claude-agent-acp's own error text (A:4510-4543). The guard samples the real
  # host. Settlement of the resulting turn through the turn runner is
  # limit_fallback_switch_test.exs's "memory limits v1.1 settlement".
  use Tightbeam.TestCase, async: false

  alias Tightbeam.{DB, MemoryGuard, Schema}
  alias Tightbeam.Acp.Adapter
  alias Tightbeam.MemoryGuard.{Cgroup, Records, Settings}

  @moduletag :memory_containment
  @moduletag timeout: 300_000
  @mib 1024 * 1024
  @host "testhost"
  @key {:claude, "shared", "testhost"}

  @agent ~S"""
  const { spawn } = require("node:child_process");
  const readline = require("node:readline");
  const send = (o) => process.stdout.write(JSON.stringify({ jsonrpc: "2.0", ...o }) + "\n");
  const exe = process.env.CLAUDE_CODE_EXECUTABLE;
  const EXIT = { code: -32603, message: "Internal error: The Claude Agent process exited unexpectedly. Please start a new session." };
  const sessions = new Map();
  let n = 0;
  const held = [];
  function start(sid, flag) {
    const child = spawn(exe, ["--output-format", "stream-json", flag + "=" + sid, "--verbose"], { stdio: ["pipe", "pipe", "inherit"] });
    const entry = { child, pending: [] };
    sessions.set(sid, entry);
    readline.createInterface({ input: child.stdout }).on("line", () => {
      const id = entry.pending.shift();
      if (id !== undefined) send({ id, result: { stopReason: "end_turn" } });
    });
    child.on("exit", () => {
      if (sessions.get(sid) === entry) sessions.delete(sid);
      for (const id of entry.pending) send({ id, error: EXIT });
      entry.pending = [];
    });
  }
  readline.createInterface({ input: process.stdin }).on("line", (line) => {
    if (!line.trim()) return;
    const m = JSON.parse(line);
    if (m.method === undefined) return;
    switch (m.method) {
      case "initialize": return send({ id: m.id, result: { protocolVersion: 1 } });
      case "session/new": { n += 1; const sid = "sess-" + process.pid + "-" + n; start(sid, "--session-id"); return send({ id: m.id, result: { sessionId: sid } }); }
      case "session/load": { start(m.params.sessionId, "--resume"); return send({ id: m.id, result: {} }); }
      case "session/prompt": {
        const text = (m.params.prompt || []).map((p) => p.text || "").join("");
        if (text === "adapter-runaway") {
          // The adapter's own memory grows without bound.
          setInterval(() => held.push(Buffer.alloc(100 << 20, 1)), 100);
          return;
        }
        const entry = sessions.get(m.params.sessionId);
        if (!entry) return send({ id: m.id, error: EXIT });
        entry.pending.push(m.id);
        entry.child.stdin.write(text + "\n");
        return;
      }
      case "session/close": {
        const entry = sessions.get(m.params.sessionId);
        if (entry) { sessions.delete(m.params.sessionId); entry.child.kill("SIGTERM"); }
        return send({ id: m.id, result: {} });
      }
      default: if (m.id !== undefined) return send({ id: m.id, result: {} });
    }
  });
  """

  # The session process. "runaway" starts a tool two levels down (sh, then
  # python) that allocates without bound; "sleep N" works for N seconds.
  @claude ~S"""
  import os, subprocess, sys, time
  out = os.environ["TB_TEST_OUT"]
  sid = next((a.split("=", 1)[1] for a in sys.argv if a.startswith(("--session-id=", "--resume="))), "none")
  open(os.path.join(out, sid + ".pid"), "w").write(str(os.getpid()))
  tool = "import os, time\nopen(os.path.join(%r, %r + '.tool'), 'w').write(str(os.getpid()))\nheld = []\nwhile True:\n    held.append(b'x' * (100 << 20))\n    time.sleep(0.1)\n" % (out, sid)
  for line in sys.stdin:
      text = line.strip()
      if text == "runaway":
          subprocess.run(["sh", "-c", "python3 -c \"$TOOL\"; echo"], env=dict(os.environ, TOOL=tool))
      elif text.startswith("sleep"):
          time.sleep(float(text.split()[1]))
      print("done", flush=True)
  """

  setup do
    outer = outer_limit!()
    expected = System.fetch_env!("TIGHTBEAM_MEMORY_CONTAINMENT_MODE")

    root = Path.join(System.tmp_dir!(), "tb-mg-contain-#{System.unique_integer([:positive])}")
    base = Path.join(root, "base")
    out = Path.join(root, "out")
    File.mkdir_p!(base)
    File.mkdir_p!(out)
    File.write!(Path.join(root, "agent.js"), @agent)
    claude = Path.join(root, "fake-claude")
    File.write!(claude, "#!/usr/bin/env python3\n" <> @claude)
    File.chmod!(claude, 0o755)
    on_exit(fn -> File.rm_rf(root) end)

    db_name = :"contain_db_#{System.unique_integer([:positive])}"
    db = start_supervised!({DB, path: ":memory:", name: db_name}, id: db_name)
    :ok = Schema.ensure_all(db)
    {:ok, total} = Tightbeam.MemoryGuard.Probe.mem_total("/")

    for {name, value} <- [{"budget", "2G"}, {"sessionLimit", "512M"}] do
      {:ok, {:ok, _}} =
        DB.transaction(db, &Settings.set_in_txn(&1, @host, name, value, "user:ci", total))
    end

    cli_bin = Path.expand("cli/target/release")

    start_supervised!(
      {MemoryGuard,
       db: db,
       base_dir: base,
       cli_bin: cli_bin,
       local_host: @host,
       root: "/",
       sample_ms: 250,
       nudge: fn _ -> :ok end}
    )

    assert %{mode: ^expected} = MemoryGuard.read(@host)

    %{db: db, root: root, base: base, out: out, claude: claude, cli_bin: cli_bin, outer: outer}
  end

  # §8: refuse unless this environment has a finite memory limit of its own.
  defp outer_limit! do
    {:ok, text} = File.read("/proc/self/cgroup")

    "0::" <> own =
      text |> String.split("\n", trim: true) |> Enum.find(&String.starts_with?(&1, "0::"))

    own
    |> Path.split()
    |> Enum.scan(&Path.join(&2, &1))
    |> Enum.reverse()
    |> Enum.find(fn cgroup ->
      case File.read(Cgroup.dir("/sys/fs/cgroup", cgroup) |> Path.join("memory.max")) do
        {:ok, "max\n"} -> false
        {:ok, _limit} -> true
        _ -> false
      end
    end)
    |> case do
      nil -> flunk("refusing to run: this environment has no finite memory limit of its own (§8)")
      cgroup -> %{cgroup: cgroup, events: local_events(cgroup)}
    end
  end

  defp local_events(cgroup) do
    {:ok, events} = Cgroup.local_events("/sys/fs/cgroup", cgroup)
    events
  end

  defp start_adapter!(ctx, launch_id) do
    env =
      MemoryGuard.launch_env(
        @key,
        launch_id,
        [cmd: [System.find_executable("node")], env: [{"CLAUDE_CODE_EXECUTABLE", ctx.claude}]],
        ctx.db
      )

    assert {_, step} = List.keyfind(env, "CLAUDE_CODE_EXECUTABLE", 0)
    assert step == Records.step_path(ctx.base)
    identity = Path.join(ctx.root, launch_id <> ".identity")

    adapter =
      start_supervised!(
        {Adapter,
         harness: :claude,
         cmd: [
           Path.join(ctx.cli_bin, "tightbeam"),
           "harness-exec",
           identity,
           launch_id,
           "--",
           System.find_executable("node"),
           Path.join(ctx.root, "agent.js")
         ],
         env: env ++ [{"TB_TEST_OUT", ctx.out}],
         home: ctx.root,
         cwd: ctx.root,
         memory_guard_key: @key,
         stderr_path: Path.join(ctx.root, launch_id <> ".stderr"),
         name: :"contain_adapter_#{launch_id}"},
        id: {:adapter, launch_id}
      )

    [pid, pgid, boot, ^launch_id] =
      identity |> wait_file!() |> String.trim() |> String.split("\t")

    # The adapter's launch row, as HarnessProcess.prepare_launch records it.
    {:ok, _} =
      DB.transaction(ctx.db, fn txn ->
        DB.Txn.q(
          txn,
          """
          INSERT INTO harness_processes
            (launchId, adapterKey, harness, preset, host, ssh, helperPath, identityPath,
             launchSequence, osPid, processGroupId, bootIdentity, identityToken, state, createdAt)
          VALUES (?1, 'claude:shared@testhost', 'claude', 'shared', 'testhost', NULL, ?2, ?3,
                  (SELECT COALESCE(MAX(launchSequence),0)+1 FROM harness_processes),
                  ?4, ?5, ?6, ?1, 'running', ?7)
          """,
          [
            launch_id,
            Path.join(ctx.cli_bin, "tightbeam"),
            identity,
            String.to_integer(pid),
            String.to_integer(pgid),
            boot,
            System.system_time(:millisecond)
          ]
        )
      end)

    %{adapter: adapter, os_pid: String.to_integer(pid)}
  end

  defp wait_file!(path, attempts \\ 400) do
    case File.read(path) do
      {:ok, text} when text != "" ->
        text

      _ when attempts > 0 ->
        Process.sleep(25)
        wait_file!(path, attempts - 1)

      _ ->
        flunk("#{path} never appeared")
    end
  end

  defp new_session!(adapter) do
    assert {:ok, sid} = Adapter.new_session(adapter, nil, "/tmp", [], "")
    sid
  end

  defp pid_of!(ctx, sid, suffix \\ ".pid"),
    do: ctx.out |> Path.join(sid <> suffix) |> wait_file!() |> String.to_integer()

  defp alive?(pid) do
    case File.read("/proc/#{pid}/stat") do
      {:ok, stat} ->
        not (stat
             |> String.split(")")
             |> List.last()
             |> String.trim_leading()
             |> String.starts_with?("Z"))

      _ ->
        false
    end
  end

  defp await_dead!(pids, attempts \\ 600) do
    cond do
      Enum.all?(pids, &(not alive?(&1))) -> :ok
      attempts == 0 -> flunk("still alive: #{inspect(Enum.filter(pids, &alive?/1))}")
      true -> Process.sleep(50) && await_dead!(pids, attempts - 1)
    end
  end

  defp record_of(ctx, sid) do
    ctx.base
    |> Records.read_all()
    |> Map.values()
    |> Enum.find(&(&1["sessionId"] == sid))
  end

  test "T1/T2: a runaway tool two levels down ends its whole session tree and only it; the adapter, the gateway and another session's turn go on",
       ctx do
    mode = System.fetch_env!("TIGHTBEAM_MEMORY_CONTAINMENT_MODE")
    %{adapter: adapter, os_pid: adapter_pid} = start_adapter!(ctx, "L1")
    a = new_session!(adapter)
    b = new_session!(adapter)
    a_pid = pid_of!(ctx, a)
    b_pid = pid_of!(ctx, b)

    # The step placed each session process as the host's mode says (R12c, AS2).
    placement = if mode == "enforced", do: "enforced", else: "watched"
    assert %{"placement" => ^placement} = record_of(ctx, a)
    {:ok, oom} = File.read("/proc/#{a_pid}/oom_score_adj")
    {:ok, adapter_oom} = File.read("/proc/#{adapter_pid}/oom_score_adj")

    assert String.to_integer(String.trim(oom)) ==
             min(String.to_integer(String.trim(adapter_oom)) + 100, 1000)

    started = System.system_time(:millisecond)
    b_turn = Task.async(fn -> Adapter.prompt(adapter, b, "sleep 20") end)
    a_turn = Task.async(fn -> Adapter.prompt(adapter, a, "runaway") end)
    tool_pid = pid_of!(ctx, a, ".tool")

    # Within 30 s the prompt ends with the harness's process-exit error.
    assert {:error, %{"code" => -32_603, "message" => message}} = Task.await(a_turn, 30_000)
    assert message =~ "The Claude Agent process exited unexpectedly"
    await_dead!([a_pid, tool_pid])

    # The adapter, the gateway and B go on; B's turn completes.
    assert Process.alive?(adapter)
    assert alive?(adapter_pid)
    assert alive?(b_pid)
    assert {:ok, %{stop_reason: "end_turn"}} = Task.await(b_turn, 30_000)

    # R10: attributed from the guard's own records, limit `session`.
    assert %{limit: "session", scope: "session"} =
             MemoryGuard.memory_kill(%{host: @host, harness_session_id: a, since: started})

    case mode do
      "enforced" ->
        layout = MemoryGuard.host_view(@host).layout
        unit = Cgroup.session_unit(layout, a)

        assert {:ok, %{"oom" => oom_count, "oom_group_kill" => group}} =
                 Cgroup.local_events(layout.fs, unit)

        assert oom_count >= 1 and group >= 1
        assert {:ok, %{"oom" => 0}} = Cgroup.local_events(layout.fs, layout.harness)

        assert {:ok, %{"oom_kill" => 0}} =
                 Cgroup.local_events(layout.fs, Cgroup.session_unit(layout, b))

        assert {:ok, %{"oom_kill" => 0}} =
                 Cgroup.local_events(layout.fs, Cgroup.adapter_unit(layout, "L1"))

        peak =
          case File.read(Path.join(Cgroup.dir(layout.fs, unit), "memory.peak")) do
            {:ok, text} -> String.trim(text)
            _ -> "unavailable"
          end

        IO.puts("T1 evidence: session unit memory.peak #{peak} (limit #{512 * @mib})")

      "watched" ->
        # T2: the overshoot bound, 512 MiB + 300 MiB, at the observed peak.
        {:ok, rows} =
          DB.query(ctx.db, "SELECT detail FROM lifecycle_events WHERE kind='memory_kill_intent'")

        assert [%{"bytes" => bytes, "limit" => "session"}] = Enum.map(rows, &JSON.decode!(hd(&1)))
        IO.puts("T2 evidence: tree memory at the kill decision #{bytes} bytes")
        assert bytes <= (512 + 300) * @mib
    end

    # The outer environment's own limit was never hit.
    after_events = local_events(ctx.outer.cgroup)
    assert Map.get(after_events, "oom", 0) == Map.get(ctx.outer.events, "oom", 0)
    assert Map.get(after_events, "oom_kill", 0) == Map.get(ctx.outer.events, "oom_kill", 0)

    # R11a: residency is cleared at once; A's next turn runs on a fresh process.
    refute Adapter.knows_session?(adapter, a)
    assert {:ok, _} = Adapter.load_session(adapter, a, nil, "/tmp", [], "")
    assert {:ok, %{stop_reason: "end_turn"}} = Adapter.prompt(adapter, a, "hello")
    assert pid_of!(ctx, a) != a_pid
  end

  test "T15: when the adapter's own memory passes the budget it ends whole, every session tree ends with it before any replacement, and the attribution is the budget",
       ctx do
    %{adapter: adapter, os_pid: adapter_pid} = start_adapter!(ctx, "L2")
    sessions = for _ <- 1..3, do: new_session!(adapter)
    session_pids = Enum.map(sessions, &pid_of!(ctx, &1))
    [a, b, _d] = sessions
    monitor = Process.monitor(adapter)
    started = System.system_time(:millisecond)

    # A and B have dispatched turns in progress; the adapter itself runs away.
    turns = for sid <- [a, b], do: Task.async(fn -> Adapter.prompt(adapter, sid, "sleep 60") end)
    _runaway = Task.async(fn -> Adapter.prompt(adapter, a, "adapter-runaway") end)

    assert_receive {:DOWN, ^monitor, :process, ^adapter, _reason}, 60_000
    for turn <- turns, do: assert({:error, _transport_loss} = Task.await(turn, 30_000))

    # What the coordinator does on the adapter's :DOWN (R2a), before any relaunch.
    :ok = MemoryGuard.adapter_ended(@key, "L2")
    await_dead!([adapter_pid | session_pids])

    # None survives reparented.
    for pid <- session_pids, do: refute(alive?(pid))

    assert %{limit: "budget", scope: "adapter"} =
             MemoryGuard.memory_kill(%{
               host: @host,
               adapter_key: @key,
               adapter_launch_id: "L2",
               since: started
             })

    assert Records.read_all(ctx.base) == %{}
  end

  test "T15 (outside kill): a SIGKILLed adapter's session trees are ended before any replacement",
       ctx do
    %{adapter: adapter, os_pid: adapter_pid} = start_adapter!(ctx, "L3")
    sessions = for _ <- 1..2, do: new_session!(adapter)
    session_pids = Enum.map(sessions, &pid_of!(ctx, &1))
    monitor = Process.monitor(adapter)
    started = System.system_time(:millisecond)

    {_, 0} = System.cmd("kill", ["-KILL", Integer.to_string(adapter_pid)])
    assert_receive {:DOWN, ^monitor, :process, ^adapter, _reason}, 30_000
    :ok = MemoryGuard.adapter_ended(@key, "L3")
    await_dead!(session_pids)

    # Not a memory kill: attribution is absent (R15 settles harness_exited).
    assert MemoryGuard.memory_kill(%{
             host: @host,
             adapter_key: @key,
             adapter_launch_id: "L3",
             since: started
           }) == nil
  end
end
