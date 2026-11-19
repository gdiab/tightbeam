defmodule Tightbeam.ReleaseCookieResolutionTest do
  # Core fix (A), C21 (core-v8.2), proven against the REAL mix-generated production
  # release and the packaged launcher in front of it, through each route a caller has:
  #
  # - K24 (C21.2): both launchers, the packaged `tightbeam-gateway` and the release's own
  #   `bin/tightbeam_gateway`, refuse every command outside their allowlist, and code a
  #   refused command carries never runs.
  # - K22 (C21.1 i): a default start registers no node and listens nowhere, and no
  #   inherited channel (each RELEASE_*, ERL_* and ELIXIR_* input the release scripts
  #   read, and a tool planted on PATH) turns distribution on or runs code.
  # - K22/K23 debug: hand-enabled debug distribution is loopback-only, registers with no
  #   EPMD even when a wildcard EPMD runs, and uses a per-install 0600 cookie.
  # - K23 (C21.1 ii-iii): the release carries no cookie.
  # - K25 (C21.3): the ungated writers are not in a production build.
  # - The gateway's `:global.trans` locks still exclude with distribution off.
  #
  # Start tests run a COPY of the release whose boot script is the kernel-only one and
  # whose own vm.args carries a probe that reports the node's distribution state. A
  # node's distribution comes from the launcher's VM flags, which the copy leaves
  # untouched, and no gateway code starts distribution, so this is the production
  # node's distribution state without the persistent-state admission a full gateway
  # boot needs. Editing installed files like this is how an operator changes an
  # install, which is outside the promise; the tests use it only to observe.
  #
  # Code checks inside the release (`eval!/2`) run its bundled Elixir runtime directly,
  # as any program of the account can: the launchers no longer offer `eval`.
  use Tightbeam.TestCase, async: false

  @moduletag :release_build

  @shim Path.expand("../packaging/tightbeam-gateway", __DIR__)
  @refused_everywhere ~w(start_iex daemon daemon_iex eval rpc remote restart iex console foreground escript reboot unknown-verb)

  setup_all do
    mix = System.find_executable("mix") || "mix"
    root = Path.join(System.tmp_dir!(), "tb-real-release-#{System.unique_integer([:positive])}")
    release_dir = Path.join(root, "pkg/release")

    {out, status} =
      System.cmd(mix, ["release", "--overwrite", "--path", release_dir],
        env: [{"MIX_ENV", "prod"}],
        stderr_to_stdout: true
      )

    assert status == 0, "mix release failed:\n#{out}"

    packaged = package!(Path.join(root, "pkg"))

    [_erts, vsn] =
      release_dir |> Path.join("releases/start_erl.data") |> File.read!() |> String.split()

    # The observation copy: kernel-only boot, and a probe in the release's own vm.args.
    probe_root = Path.join(root, "probe")
    File.mkdir_p!(probe_root)
    {_, 0} = System.cmd("cp", ["-R", release_dir, Path.join(probe_root, "release")])
    probe_vsn_dir = Path.join(probe_root, "release/releases/#{vsn}")
    File.cp!(Path.join(probe_vsn_dir, "start_clean.boot"), Path.join(probe_vsn_dir, "start.boot"))

    File.write!(
      Path.join(probe_vsn_dir, "vm.args"),
      "-eval erlang:display({tbprobe,node(),erlang:is_alive()})\n",
      [:append]
    )

    on_exit(fn -> File.rm_rf!(root) end)

    %{
      root: root,
      launcher: Path.join(release_dir, "bin/tightbeam_gateway"),
      packaged: packaged,
      release_dir: release_dir,
      probe_packaged: package!(probe_root),
      probe_raw: Path.join(probe_root, "release/bin/tightbeam_gateway")
    }
  end

  defp package!(dir) do
    File.mkdir_p!(Path.join(dir, "bin"))
    packaged = Path.join(dir, "bin/tightbeam-gateway")
    File.cp!(@shim, packaged)
    File.chmod!(packaged, 0o755)
    packaged
  end

  # Runs `code` in the release's own VM through its bundled Elixir runtime, with the
  # kernel-only boot (every module loaded, no application started).
  defp eval!(launcher, code) do
    release = launcher |> Path.dirname() |> Path.dirname()

    [_erts, vsn] =
      release |> Path.join("releases/start_erl.data") |> File.read!() |> String.split()

    vsn_dir = Path.join(release, "releases/#{vsn}")

    {out, status} =
      System.cmd(
        Path.join(vsn_dir, "elixir"),
        [
          "--boot",
          Path.join(vsn_dir, "start_clean"),
          "--boot-var",
          "RELEASE_LIB",
          Path.join(release, "lib"),
          "--eval",
          code
        ],
        stderr_to_stdout: true
      )

    assert status == 0, out
    out
  end

  defp value(out, key) do
    [value] = Regex.run(~r/^#{key}=(.*)$/m, out, capture: :all_but_first)
    value
  end

  test "K23: the release carries no cookie", %{release_dir: release_dir} do
    assert Path.wildcard(Path.join(release_dir, "**/COOKIE"), match_dot: true) == []
    assert Path.wildcard(Path.join(release_dir, "**/.erlang.cookie"), match_dot: true) == []
  end

  test "K24 (C21.2): both launchers refuse every command outside their allowlist, and run nothing",
       %{packaged: packaged, launcher: launcher, root: root} do
    marker = Path.join(root, "k24-ran")
    code = "File.write!(#{inspect(marker)}, \"ran\")"

    for {entry, verbs} <- [
          {packaged, @refused_everywhere},
          {launcher, @refused_everywhere ++ ~w(stop pid)}
        ],
        verb <- verbs do
      {out, status} =
        System.cmd(entry, [verb, code], stderr_to_stdout: true, env: [{"RELEASE_NODE", "evil"}])

      assert status == 64, "#{entry} #{verb}: #{out}"
      assert out =~ "C21.2", "#{entry} #{verb}: #{out}"
    end

    refute File.exists?(marker)

    # The allowlisted read-only verb still answers on both.
    for entry <- [packaged, launcher] do
      assert {"tightbeam_gateway " <> _, 0} =
               System.cmd(entry, ["version"], stderr_to_stdout: true)
    end
  end

  test "K22 (C21.1): a default start registers no node and listens nowhere",
       %{probe_packaged: probe_packaged} do
    {port, os_pid, boot} = start!(probe_packaged, [])

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
      refute_registered("tightbeam_gateway")
    after
      stop!(port, os_pid)
    end
  end

  test "K22 (C21.1): no inherited flag channel turns distribution on or runs code",
       %{root: root, probe_packaged: probe_packaged, probe_raw: probe_raw} do
    dir = Path.join(root, "channels")
    File.mkdir_p!(dir)
    marker = Path.join(dir, "ran")
    inject = "-sname evil -eval file:write_file(\"#{marker}\",<<\"x\">>)"
    evil_args = Path.join(dir, "evil.vm.args")
    File.write!(evil_args, inject <> "\n")
    evil_config = Path.join(dir, "evil")
    File.write!(evil_config <> ".config", "not an erlang term")
    evil_tmp = Path.join(dir, "evil-tmp")
    evil_libs = Path.join(dir, "evil-libs")
    File.mkdir_p!(evil_libs)
    inetrc = Path.join(dir, "inetrc")
    File.write!(inetrc, "{file, hosts, \"/nonexistent\"}.\n")

    # A `sed` planted ahead of the system's, as on a PATH with user-writable entries.
    plant = Path.join(dir, "plant")
    File.mkdir_p!(plant)
    sed = Path.join(plant, "sed")
    File.write!(sed, "#!/bin/sh\necho planted > #{inspect(marker)}\nexec /usr/bin/sed \"$@\"\n")
    File.chmod!(sed, 0o755)

    release_channels = [
      {"RELEASE_DISTRIBUTION", "sname"},
      {"RELEASE_NODE", "evil"},
      {"RELEASE_COOKIE", "inherited-cookie"},
      {"RELEASE_VM_ARGS", evil_args},
      {"RELEASE_REMOTE_VM_ARGS", evil_args},
      {"RELEASE_BOOT_SCRIPT", "no-such-boot"},
      {"RELEASE_BOOT_SCRIPT_CLEAN", "no-such-boot"},
      {"RELEASE_MODE", "embedded -sname evil"},
      {"RELEASE_SYS_CONFIG", evil_config},
      {"RELEASE_TMP", evil_tmp},
      {"RELEASE_NAME", "evil"},
      {"RELEASE_PROG", "evil"}
    ]

    flag_channels = [
      {"ELIXIR_ERL_OPTIONS", inject},
      {"ERL_AFLAGS", inject},
      {"ERL_FLAGS", inject},
      {"ERL_ZFLAGS", inject},
      {"ERL_LIBS", evil_libs},
      {"ERL_EPMD_PORT", "1"},
      {"ERL_ROOTDIR", "/nonexistent"},
      {"ERL_INETRC", inetrc}
    ]

    # RELEASE_VSN and PATH are read before the release's env.sh runs, so only the
    # packaged launcher can clear them; a caller who sets them on the raw launcher
    # chooses which files run, which is running code of their own.
    packaged_only = [
      {"RELEASE_VSN", "../../channels"},
      {"PATH", plant <> ":" <> System.get_env("PATH", "/usr/bin:/bin")}
    ]

    for {entry, channels} <- [
          {probe_packaged, release_channels ++ flag_channels ++ packaged_only},
          {probe_raw, release_channels ++ flag_channels}
        ],
        {name, value} <- channels do
      {port, os_pid, boot} = start!(entry, [{name, value}])
      stop!(port, os_pid)

      assert boot =~ "{tbprobe,'nonode@nohost',false}", "#{entry} #{name}: #{boot}"
      refute File.exists?(marker), "#{entry} #{name} ran injected code"
      refute File.exists?(evil_tmp), "#{entry} #{name} wrote into an inherited RELEASE_TMP"
    end
  end

  test "K22/K23: hand-enabled debug distribution is loopback-only, registers with no EPMD, and uses a per-install 0600 cookie",
       %{root: root, probe_packaged: probe_packaged, release_dir: release_dir} do
    base = Path.join(root, "debug-base-#{System.unique_integer([:positive])}")
    File.mkdir_p!(base)
    gateway_port = free_port()
    dist_port = free_port()
    node_name = "tightbeam_gateway_#{gateway_port}@127.0.0.1"

    # A wildcard EPMD on the default port, as the old gateway left one: start one when
    # none runs, and leave an existing one alone.
    epmd = wildcard_epmd!(release_dir)

    debug_env = [
      {"TIGHTBEAM_DEBUG_DISTRIBUTION", "loopback:#{dist_port}"},
      {"TIGHTBEAM_BASE_DIR", base},
      {"TIGHTBEAM_PORT", Integer.to_string(gateway_port)}
    ]

    {port, os_pid, boot} = start!(probe_packaged, debug_env)

    try do
      assert boot =~ "{tbprobe,'#{node_name}',true}"

      # K23: the per-install cookie, generated at this first start.
      cookie_file = Path.join(base, "debug-distribution.cookie")
      %File.Stat{type: :regular, mode: mode, uid: uid} = File.stat!(cookie_file)
      assert Bitwise.band(mode, 0o777) == 0o600
      {own_uid, 0} = System.cmd("id", ["-u"])
      assert Integer.to_string(uid) == String.trim(own_uid)
      cookie = File.read!(cookie_file)
      assert cookie =~ ~r/\A[0-9a-f]{64}\z/

      # K22: the node's only listener is the named port on loopback.
      assert listening_addresses(listeners(os_pid)) == [{"127.0.0.1", dist_port}]

      # No EPMD, wildcard or loopback, learned of it.
      refute_registered("tightbeam_gateway_#{gateway_port}")

      # From a non-loopback address, the distribution port refuses.
      assert {:error, _} = :gen_tcp.connect(non_loopback_ip(), dist_port, [], 2_000)

      # Control: on loopback, with this install's cookie, the node is reachable.
      erl = System.find_executable("erl") || flunk("erl is required for the loopback control")

      {out, 0} =
        System.cmd(
          erl,
          ~w(-noshell -name tb_ctl_#{System.unique_integer([:positive])}@127.0.0.1 -setcookie #{cookie}
             -start_epmd false -dist_listen false -erl_epmd_port #{dist_port}) ++
            [
              "-eval",
              "io:format(\"~p~n\", [rpc:call('#{node_name}', erlang, node, [])]), halt()."
            ],
          stderr_to_stdout: true
        )

      assert out =~ node_name
    after
      stop!(port, os_pid)
      epmd.()
    end

    # Malformed or widened settings refuse to start.
    for value <- ~w(loopback loopback:80 loopback:x loopback:70000 wildcard:#{dist_port}) do
      {out, status} =
        System.cmd(probe_packaged, ["start"],
          env: [{"TIGHTBEAM_DEBUG_DISTRIBUTION", value}, {"TIGHTBEAM_BASE_DIR", base}],
          stderr_to_stdout: true
        )

      assert status == 1, "#{value}: #{out}"
      assert out =~ "TIGHTBEAM_DEBUG_DISTRIBUTION"
    end
  end

  test "K25 (C21.3): a production build carries none of the ungated in-process writers",
       %{launcher: launcher} do
    out =
      eval!(launcher, ~S"""
      for {m, f, a} <- [
            {Tightbeam.Devices, :approve, 3},
            {Tightbeam.Devices, :deny, 2},
            {Tightbeam.Devices, :revoke, 2},
            {Tightbeam.Devices, :add_user, 3},
            {Tightbeam.Devices, :set_user_admin, 3},
            {Tightbeam.Placement, :register_host, 3},
            {Tightbeam.DeviceLifecycle, :insert_code_in_txn, 9},
            {Tightbeam.DeviceLifecycle, :enroll_in_txn, 5},
            {Tightbeam.DeviceLifecycle, :issue_code, 3}
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
          "EXPORTED {Tightbeam.DeviceLifecycle, :insert_code_in_txn, 9}=false",
          "EXPORTED {Tightbeam.DeviceLifecycle, :enroll_in_txn, 5}=false",
          # The gated writer stays: it is the production path.
          "EXPORTED {Tightbeam.DeviceLifecycle, :issue_code, 3}=true"
        ] do
      assert out =~ line, out
    end
  end

  test "the production release carries and loads the native helpers", %{launcher: launcher} do
    # Stage 1: the Argon2id and base-lock NIF ships in the release's priv and loads
    # there. The vector is the CLI's (cli/src/device_recovery_vector.txt).
    vector =
      Path.expand("../cli/src/device_recovery_vector.txt", __DIR__)
      |> File.read!()
      |> String.trim()

    lock = Path.join(System.tmp_dir!(), "tb-release-nif-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm(lock) end)

    out =
      eval!(launcher, ~s"""
      verifier = Tightbeam.Native.argon2id("TB-7K3M-Q9ZD-2WH8", :binary.copy(<<7>>, 16))
      IO.puts("ARGON2=" <> Base.encode16(verifier, case: :lower))
      held = Tightbeam.Native.base_lock(#{inspect(lock)})
      IO.puts("LOCK=" <> to_string(is_reference(held)))
      """)

    assert value(out, "ARGON2") == vector
    assert value(out, "LOCK") == "true"
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

  # Start `entry start` with `env` and return {port, os_pid, the probe's report}.
  defp start!(entry, env) do
    env = Enum.map(env, fn {k, v} -> {String.to_charlist(k), String.to_charlist(v)} end)

    port =
      Port.open({:spawn_executable, entry}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        args: ["start"],
        env: env
      ])

    {:os_pid, os_pid} = Port.info(port, :os_pid)
    # The whole probe term: output can arrive split across reads.
    {port, Integer.to_string(os_pid), collect_until(port, ~r/\{tbprobe,[^}]*\}/, 30_000)}
  end

  defp stop!(port, os_pid) do
    System.cmd("kill", ["-KILL", os_pid], stderr_to_stdout: true)
    if Port.info(port), do: Port.close(port)
  end

  # Ensure a wildcard EPMD on the default port; returns its cleanup.
  defp wildcard_epmd!(release_dir) do
    case :gen_tcp.connect({127, 0, 0, 1}, 4369, [], 1_000) do
      {:ok, socket} ->
        :gen_tcp.close(socket)
        fn -> :ok end

      {:error, _} ->
        epmd = release_dir |> Path.join("erts-*/bin/epmd") |> Path.wildcard() |> hd()
        {_, 0} = System.cmd(epmd, ["-daemon"], env: [{"ERL_EPMD_ADDRESS", nil}])
        wait_for_epmd()

        fn ->
          {pids, _} = System.cmd("lsof", ["-t", "-iTCP:4369", "-sTCP:LISTEN"])
          for pid <- String.split(pids), do: System.cmd("kill", [pid], stderr_to_stdout: true)
        end
    end
  end

  defp wait_for_epmd(tries \\ 50) do
    case :gen_tcp.connect({127, 0, 0, 1}, 4369, [], 200) do
      {:ok, socket} ->
        :gen_tcp.close(socket)

      {:error, _} when tries > 0 ->
        Process.sleep(100)
        wait_for_epmd(tries - 1)

      {:error, reason} ->
        flunk("the test EPMD did not start: #{inspect(reason)}")
    end
  end

  # The exact node name only: another program's nodes may share the host's EPMD.
  defp refute_registered(name) do
    for host <- [non_loopback_ip(), {127, 0, 0, 1}] do
      case :erl_epmd.names(host) do
        {:ok, names} -> refute Enum.any?(names, fn {node, _port} -> to_string(node) == name end)
        {:error, _no_epmd} -> :ok
      end
    end
  end

  defp listeners(pid) do
    {out, _status} =
      System.cmd("lsof", ["-w", "-nP", "-a", "-p", pid, "-iTCP", "-sTCP:LISTEN"],
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
