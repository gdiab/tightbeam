defmodule Tightbeam.ReleaseCookieResolutionTest do
  # Core fix (A), C21 (core-v8.2), proven against the REAL mix-generated production
  # release and the packaged launcher in front of it:
  #
  # - K22 (C21.1 i): by default the gateway starts with no distribution and no EPMD,
  #   so nothing listens; a hand-enabled debug distribution listens on loopback only.
  # - K23 (C21.1 ii-iii): the release carries no cookie; debug distribution generates
  #   a per-install cookie at first start, 256 random bits, 0600, this account's.
  # - K24 (C21.2): the launcher's rpc, remote and eval are refused against a running
  #   default install, and the release's own rpc and remote reach nothing.
  # - C21.3: the ungated writers are not in a production build.
  # - The gateway's `:global.trans` locks still exclude with distribution off.
  #
  # The start tests boot the packaged launcher's `start` with the kernel-only boot
  # script. A node's distribution comes from the launcher's VM flags, and no gateway
  # code starts distribution, so this is the production node's distribution state
  # without the persistent-state admission a full gateway boot needs.
  #
  # Builds the real release ONCE in setup_all. Kept in the default gate on purpose: a
  # proof against reality has to actually run to count.
  use Tightbeam.TestCase, async: false

  @moduletag :release_build

  @shim Path.expand("../packaging/tightbeam-gateway", __DIR__)

  setup_all do
    mix = System.find_executable("mix") || "mix"
    root = Path.join(System.tmp_dir!(), "tb-real-release-#{System.unique_integer([:positive])}")
    release_dir = Path.join(root, "release")

    {out, status} =
      System.cmd(mix, ["release", "--overwrite", "--path", release_dir],
        env: [{"MIX_ENV", "prod"}],
        stderr_to_stdout: true
      )

    assert status == 0, "mix release failed:\n#{out}"

    # The package layout: the launcher at bin/, the release beside it.
    File.mkdir_p!(Path.join(root, "bin"))
    packaged = Path.join(root, "bin/tightbeam-gateway")
    File.cp!(@shim, packaged)
    File.chmod!(packaged, 0o755)
    on_exit(fn -> File.rm_rf!(root) end)

    %{
      launcher: Path.join(release_dir, "bin/tightbeam_gateway"),
      packaged: packaged,
      release_dir: release_dir
    }
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

  test "K23: the release carries no cookie, and distribution stays off over inherited values",
       %{launcher: launcher, release_dir: release_dir} do
    assert Path.wildcard(Path.join(release_dir, "**/COOKIE"), match_dot: true) == []
    assert Path.wildcard(Path.join(release_dir, "**/.erlang.cookie"), match_dot: true) == []

    expr =
      ~S[IO.puts("DIST=" <> (System.get_env("RELEASE_DISTRIBUTION") || "nil")); IO.puts("TBCOOKIE=" <> (System.get_env("RELEASE_COOKIE") || "nil"))]

    runs =
      for env <- [
            [],
            [],
            [{"RELEASE_DISTRIBUTION", "sname"}, {"RELEASE_COOKIE", "inherited-cookie"}]
          ],
          do: eval!(launcher, expr, env)

    for out <- runs, do: assert(value(out, "DIST") == "none")

    # The per-start value is a throwaway nothing uses; it is never an inherited one.
    cookies = for out <- runs, do: value(out, "TBCOOKIE")
    refute "inherited-cookie" in cookies
    assert cookies |> Enum.uniq() |> length() == 3
  end

  test "K22/K24: a default packaged gateway listens nowhere, and rpc, remote and eval reach nothing",
       %{launcher: launcher, packaged: packaged, release_dir: release_dir} do
    node_name = "tb_c21_probe_#{System.unique_integer([:positive])}"
    marker = Path.join(release_dir, "k24-#{System.unique_integer([:positive])}")

    # The inherited values that would make it a named node, absent the fix.
    {port, os_pid, boot} =
      start!(packaged, release_dir, [
        {"RELEASE_DISTRIBUTION", "sname"},
        {"RELEASE_NODE", node_name}
      ])

    try do
      assert boot =~ "{tbprobe,'nonode@nohost',false}"

      # No listening TCP socket at all, so no distribution port to reach. The control
      # proves the probe sees a listener when one exists.
      {:ok, control} = :gen_tcp.listen(0, [])
      {:ok, control_port} = :inet.port(control)
      assert listeners(System.pid()) =~ ":#{control_port} (LISTEN)"
      :gen_tcp.close(control)
      refute listeners(os_pid) =~ "LISTEN"

      # EPMD, asked from a non-loopback address and from loopback, knows no such node.
      for host <- [non_loopback_ip(), {127, 0, 0, 1}] do
        case :erl_epmd.names(host) do
          {:ok, names} ->
            refute Enum.any?(names, fn {name, _} -> to_string(name) == node_name end)

          {:error, _no_epmd} ->
            :ok
        end
      end

      # K24: the packaged launcher refuses each, naming C21.2, and runs nothing.
      code = "File.write!(#{inspect(marker)}, \"ran\")"

      for args <- [["rpc", code], ["remote"], ["eval", code]] do
        {out, status} =
          System.cmd(packaged, args, env: [{"RELEASE_NODE", node_name}], stderr_to_stdout: true)

        assert status == 64, out
        assert out =~ "is not available (C21.2)"
      end

      # The release's own rpc and remote, bypassing the launcher, reach no node either.
      for args <- [["rpc", code], ["remote"]] do
        {out, status} =
          System.cmd(launcher, args,
            env: [{"RELEASE_NODE", node_name}, {"RELEASE_DISTRIBUTION", "sname"}],
            stderr_to_stdout: true
          )

        assert status != 0, out
      end

      refute File.exists?(marker)
    after
      stop!(port, os_pid)
    end
  end

  test "K22/K23: hand-enabled debug distribution is loopback-only, with a per-install 0600 cookie",
       %{launcher: launcher, packaged: packaged, release_dir: release_dir} do
    base = Path.join(release_dir, "debug-base-#{System.unique_integer([:positive])}")
    File.mkdir_p!(base)
    gateway_port = free_port()
    epmd_port = free_port()
    node_name = "tightbeam_gateway_#{gateway_port}@127.0.0.1"

    # An EPMD of this test's own, so the test gate's EPMD plays no part.
    debug_env = [
      {"TIGHTBEAM_DEBUG_DISTRIBUTION", "loopback"},
      {"TIGHTBEAM_BASE_DIR", base},
      {"TIGHTBEAM_PORT", Integer.to_string(gateway_port)},
      {"ERL_EPMD_PORT", Integer.to_string(epmd_port)}
    ]

    {port, os_pid, boot} = start!(packaged, release_dir, debug_env)

    try do
      assert boot =~ "{tbprobe,'#{node_name}',true}"

      # K23: the per-install cookie, generated at this first start.
      cookie_file = Path.join(base, "debug-distribution.cookie")
      %File.Stat{type: :regular, mode: mode, uid: uid} = File.stat!(cookie_file)
      assert Bitwise.band(mode, 0o777) == 0o600
      {own_uid, 0} = System.cmd("id", ["-u"])
      assert Integer.to_string(uid) == String.trim(own_uid)
      assert File.read!(cookie_file) =~ ~r/\A[0-9a-f]{64}\z/

      # K22: every listener of the node and of its EPMD is on loopback.
      node_listeners = listening_addresses(listeners(os_pid))
      epmd_listeners = listening_addresses(port_listeners(epmd_port))
      assert node_listeners != [] and epmd_listeners != []

      for {address, _port} <- node_listeners ++ epmd_listeners,
          do: assert(address in ["127.0.0.1", "[::1]"], inspect(node_listeners ++ epmd_listeners))

      # From a non-loopback address, the distribution port and EPMD refuse.
      ip = non_loopback_ip()

      for {_address, listen_port} <- node_listeners ++ epmd_listeners do
        assert {:error, _} = :gen_tcp.connect(ip, listen_port, [], 2_000)
      end

      # Control: on loopback, with this install's cookie, the node is reachable.
      {out, 0} =
        System.cmd(launcher, ["rpc", "IO.puts(:tb_debug_reached)"],
          env: debug_env,
          stderr_to_stdout: true
        )

      assert out =~ "tb_debug_reached"
    after
      stop!(port, os_pid)

      # This test's own EPMD, found by the port it alone listens on.
      {pids, _} = System.cmd("lsof", ["-t", "-iTCP:#{epmd_port}", "-sTCP:LISTEN"])
      for pid <- String.split(pids), do: System.cmd("kill", [pid], stderr_to_stdout: true)
    end
  end

  test "K25 (C21.3): a production build carries none of the ungated in-process writers", %{
    launcher: launcher
  } do
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

  # Start the packaged launcher's `start` with the kernel-only boot script and an
  # eval in the node's own boot that reports its distribution state; everything else
  # on the command line is the launcher's.
  defp start!(packaged, release_dir, env) do
    vm_args = Path.join(release_dir, "probe-#{System.unique_integer([:positive])}.vm.args")
    File.write!(vm_args, "-eval erlang:display({tbprobe,node(),erlang:is_alive()})\n")

    env =
      [{"RELEASE_VM_ARGS", vm_args}, {"RELEASE_BOOT_SCRIPT", "start_clean"} | env]
      |> Enum.map(fn {k, v} -> {String.to_charlist(k), String.to_charlist(v)} end)

    port =
      Port.open({:spawn_executable, packaged}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        args: ["start"],
        env: env
      ])

    {:os_pid, os_pid} = Port.info(port, :os_pid)
    {port, Integer.to_string(os_pid), collect_until(port, "{tbprobe,", 30_000)}
  end

  defp stop!(port, os_pid) do
    System.cmd("kill", ["-KILL", os_pid], stderr_to_stdout: true)
    if Port.info(port), do: Port.close(port)
  end

  defp port_listeners(tcp_port) do
    {out, _status} =
      System.cmd("lsof", ["-w", "-nP", "-iTCP:#{tcp_port}", "-sTCP:LISTEN"],
        stderr_to_stdout: true
      )

    out
  end

  defp listening_addresses(lsof) do
    for [address, port] <-
          Regex.scan(~r/TCP (\S+):(\d+) \(LISTEN\)/, lsof, capture: :all_but_first),
        do: {address, String.to_integer(port)}
  end

  defp non_loopback_ip do
    {:ok, interfaces} = :inet.getifaddrs()

    Enum.find_value(interfaces, fn {_name, opts} ->
      Enum.find_value(Keyword.get_values(opts, :addr), fn
        {127, _, _, _} -> nil
        {169, 254, _, _} -> nil
        {_, _, _, _} = ip -> if :up in Keyword.get(opts, :flags, []), do: ip
        _ -> nil
      end)
    end) || flunk("this host has no non-loopback IPv4 address to test from")
  end

  defp free_port do
    {:ok, socket} = :gen_tcp.listen(0, [])
    {:ok, port} = :inet.port(socket)
    :gen_tcp.close(socket)
    port
  end
end
