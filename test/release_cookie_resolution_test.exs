defmodule Tightbeam.ReleaseCookieResolutionTest do
  # Core fix (A), review B1, proven against the REAL mix-generated production release:
  # the gateway runs without Erlang distribution, so no process (an agent running as
  # the gateway's account included) can run code inside the live node through `rpc`
  # or `remote`, no distribution port listens, and no packaged cookie authenticates
  # anything.
  #
  # The start-path test boots the release's own `start` command with the kernel-only
  # boot script: the node's distribution comes from the launcher's VM flags, and no
  # gateway code starts distribution, so this is the production node's distribution
  # state without the persistent-state admission a full gateway boot needs.
  #
  # Builds the real release ONCE in setup_all. Kept in the default gate on purpose: a
  # proof against reality has to actually run to count.
  use Tightbeam.TestCase, async: false

  @moduletag :release_build

  setup_all do
    mix = System.find_executable("mix") || "mix"

    release_dir =
      Path.join(System.tmp_dir!(), "tb-real-release-#{System.unique_integer([:positive])}")

    {out, status} =
      System.cmd(mix, ["release", "--overwrite", "--path", release_dir],
        env: [{"MIX_ENV", "prod"}],
        stderr_to_stdout: true
      )

    assert status == 0, "mix release failed:\n#{out}"

    launcher = Path.join(release_dir, "bin/tightbeam_gateway")
    baked = release_dir |> Path.join("releases/COOKIE") |> File.read!() |> String.trim()
    on_exit(fn -> File.rm_rf!(release_dir) end)

    %{launcher: launcher, baked: baked, release_dir: release_dir}
  end

  defp eval!(launcher, expr, env \\ []) do
    {out, status} = System.cmd(launcher, ["eval", expr], env: env, stderr_to_stdout: true)
    assert status == 0, out
    out
  end

  defp value(out, key) do
    [value] = Regex.run(~r/^#{key}=(.*)$/m, out, capture: :all_but_first)
    value
  end

  test "the release forces distribution off and a fresh cookie over inherited values",
       %{launcher: launcher, baked: baked} do
    expr =
      ~S[IO.puts("DIST=" <> (System.get_env("RELEASE_DISTRIBUTION") || "nil")); IO.puts("TBCOOKIE=" <> (System.get_env("RELEASE_COOKIE") || "nil"))]

    first = eval!(launcher, expr)
    second = eval!(launcher, expr)

    inherited =
      eval!(launcher, expr, [{"RELEASE_DISTRIBUTION", "sname"}, {"RELEASE_COOKIE", baked}])

    for out <- [first, second, inherited], do: assert(value(out, "DIST") == "none")

    cookies = for out <- [first, second, inherited], do: value(out, "TBCOOKIE")
    refute baked in cookies
    assert cookies |> Enum.uniq() |> length() == 3
    assert Enum.all?(cookies, &(&1 =~ ~r/\A[0-9a-f]{64}\z/))
  end

  test "the real start path registers no node, listens on no port, and rpc/remote reach nothing",
       %{launcher: launcher, release_dir: release_dir} do
    node_name = "tb_b1_probe_#{System.unique_integer([:positive])}"

    # An eval in the node's own boot reports its distribution state; everything else
    # on the command line is the launcher's.
    vm_args = Path.join(release_dir, "probe.vm.args")
    File.write!(vm_args, "-eval erlang:display({tbprobe,node(),erlang:is_alive()})\n")

    port =
      Port.open({:spawn_executable, launcher}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        args: ["start"],
        env: [
          {~c"RELEASE_VM_ARGS", String.to_charlist(vm_args)},
          {~c"RELEASE_BOOT_SCRIPT", ~c"start_clean"},
          # The inherited values that would make it a named node, absent the fix.
          {~c"RELEASE_DISTRIBUTION", ~c"sname"},
          {~c"RELEASE_NODE", String.to_charlist(node_name)}
        ]
      ])

    {:os_pid, os_pid} = Port.info(port, :os_pid)

    try do
      assert collect_until(port, "{tbprobe,", 30_000) =~ "{tbprobe,'nonode@nohost',false}"

      # No node name registered with epmd.
      case :erl_epmd.names() do
        {:ok, names} -> refute Enum.any?(names, fn {name, _} -> to_string(name) == node_name end)
        {:error, _no_epmd} -> :ok
      end

      # No listening TCP socket at all, so no distribution port to reach. The control
      # proves the probe sees a listener when one exists.
      {:ok, control} = :gen_tcp.listen(0, [])
      {:ok, control_port} = :inet.port(control)
      assert listeners(System.pid()) =~ ":#{control_port} (LISTEN)"
      :gen_tcp.close(control)
      refute listeners(to_string(os_pid)) =~ "LISTEN"

      # The release's own rpc and remote, bypassing the packaged launcher's refusal.
      for args <- [["rpc", "IO.puts(:tb_b1_reached)"], ["remote"]] do
        {out, status} =
          System.cmd(launcher, args,
            env: [{"RELEASE_NODE", node_name}, {"RELEASE_DISTRIBUTION", "sname"}],
            stderr_to_stdout: true
          )

        assert status != 0, out
        refute out =~ "tb_b1_reached"
      end
    after
      System.cmd("kill", ["-KILL", to_string(os_pid)], stderr_to_stdout: true)
      if Port.info(port), do: Port.close(port)
    end
  end

  test "a production build carries none of the ungated in-process writers", %{launcher: launcher} do
    out =
      eval!(launcher, ~S"""
      for {m, f, a} <- [
            {Tightbeam.Devices, :approve, 3},
            {Tightbeam.Devices, :deny, 2},
            {Tightbeam.Devices, :revoke, 2},
            {Tightbeam.Devices, :add_user, 3},
            {Tightbeam.Devices, :set_user_admin, 3},
            {Tightbeam.Placement, :register_host, 3},
            {Tightbeam.Devices, :approve_with_firehose, 4}
          ] do
        {:module, ^m} = Code.ensure_loaded(m)
        IO.puts("EXPORTED #{inspect({m, f, a})}=#{function_exported?(m, f, a)}")
      end
      """)

    for line <- [
          "EXPORTED {Tightbeam.Devices, :approve, 3}=false",
          "EXPORTED {Tightbeam.Devices, :deny, 2}=false",
          "EXPORTED {Tightbeam.Devices, :revoke, 2}=false",
          "EXPORTED {Tightbeam.Devices, :add_user, 3}=false",
          "EXPORTED {Tightbeam.Devices, :set_user_admin, 3}=false",
          "EXPORTED {Tightbeam.Placement, :register_host, 3}=false",
          # The gated writer stays: it is the production path.
          "EXPORTED {Tightbeam.Devices, :approve_with_firehose, 4}=true"
        ] do
      assert out =~ line, out
    end
  end

  test "the gateway's :global.trans locks still exclude with distribution off",
       %{launcher: launcher} do
    # The lock ids of the eight `:global.trans` call sites (identity.ex x2,
    # harklight_send.ex x2 sharing one shape, harklight_lifecycle.ex x2, gateway.ex
    # x2), taken in the production release's non-distributed VM by two contenders
    # each.
    out =
      eval!(launcher, ~S"""
      false = Node.alive?()
      parent = self()

      locks = [
        {Tightbeam.Identity, :init, "/tmp/identity"},
        {Tightbeam.Identity, :live_revision, "/tmp/identity"},
        {Tightbeam.HarklightSend, :db, "op-1"},
        {Tightbeam.HarklightLifecycle, :db, "handle", "event"},
        {Tightbeam.HarklightLifecycle, :db, :answer_completion},
        {Tightbeam.Gateway, :session_mutation, "agent:test"},
        {Tightbeam.Gateway, :home_pin, "claude", "host"}
      ]

      contend = fn lock, name ->
        spawn(fn ->
          :global.trans({lock, self()}, fn ->
            send(parent, {:in, name})
            Process.sleep(150)
            send(parent, {:out, name})
          end)
        end)
      end

      for lock <- locks do
        contend.(lock, :a)
        Process.sleep(20)
        contend.(lock, :b)

        events =
          for _ <- 1..4 do
            receive do
              event -> event
            after
              5_000 -> :timeout
            end
          end

        [{:in, :a}, {:out, :a}, {:in, :b}, {:out, :b}] = events
      end

      IO.puts("GLOBAL_EXCLUSIVE=#{length(locks)}")
      """)

    assert out =~ "GLOBAL_EXCLUSIVE=7"
  end

  defp listeners(pid) do
    {out, _status} =
      System.cmd("lsof", ["-w", "-nP", "-a", "-p", pid, "-iTCP", "-sTCP:LISTEN"],
        stderr_to_stdout: true
      )

    out
  end

  defp collect_until(port, marker, timeout, acc \\ "") do
    receive do
      {^port, {:data, data}} ->
        acc = acc <> data
        if acc =~ marker, do: acc, else: collect_until(port, marker, timeout, acc)

      {^port, {:exit_status, status}} ->
        flunk("the release exited (#{status}) before reporting:\n#{acc}")
    after
      timeout -> flunk("no probe output within #{timeout}ms:\n#{acc}")
    end
  end
end
