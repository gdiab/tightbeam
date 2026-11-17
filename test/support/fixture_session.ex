defmodule Tightbeam.FixtureSession do
  @moduledoc false

  # Some tests exercise the CLI's session discovery itself: they write a
  # .tightbeam-session under the sandbox naming one of their own loopback Bandit
  # listeners (or a port they closed on purpose) and run the CLI from inside
  # that tree. Tightbeam.TestIsolation refuses every session ancestor, so these
  # launches go through here instead (F1, wi_34a7be66; reviewer ruling on
  # session_cli). write!/2 writes such a file and records its exact path and
  # URL. cmd/3 and port_open/2 accept the nearest session file only if it lies
  # inside the sandbox, names a loopback address, and carries exactly the URL
  # recorded for that file (the live gateway is on loopback too, so loopback
  # alone is not enough); then they apply the isolation helper's cwd and env
  # rules. A launch with no session ancestor goes to Tightbeam.TestIsolation.

  alias Tightbeam.{TestIsolation, TestSandboxPreflight}

  @recorded {__MODULE__, :recorded}

  @doc """
  Write a fixture .tightbeam-session at `path` and record its URL. The file
  may only be written inside the sandbox or the test tmp root.
  """
  def write!(path, fields) do
    dir = path |> Path.expand() |> Path.dirname() |> TestSandboxPreflight.canonical()

    unless TestSandboxPreflight.inside?(dir, TestIsolation.sandbox_root()) or
             TestSandboxPreflight.inside?(dir, TestIsolation.test_tmp()),
           do: refuse!("a fixture session may not be written at #{path}")

    File.write!(path, JSON.encode!(fields))
    recorded = :persistent_term.get(@recorded, %{})
    key = TestSandboxPreflight.canonical(path)
    :persistent_term.put(@recorded, Map.put(recorded, key, Map.fetch!(fields, :url)))
  end

  @doc "System.cmd/3 from inside a fixture session tree."
  def cmd(command, args, opts \\ []) do
    case session_for(Keyword.get(opts, :cd)) do
      nil ->
        TestIsolation.cmd(command, args, opts)

      {session, cd} ->
        check!(session, cd)
        TestIsolation.executable!(command, cd)
        TestIsolation.env!(Keyword.get(opts, :env, []))
        System.cmd(command, args, opts)
    end
  end

  @doc "Port.open/2 from inside a fixture session tree."
  def port_open(name, opts) do
    cd = with {:cd, value} <- List.keyfind(opts, :cd, 0), do: to_string(value)

    case session_for(cd) do
      nil ->
        TestIsolation.port_open(name, opts)

      {session, cd} ->
        check!(session, cd)

        TestIsolation.port_executable!(name, cd)

        declared =
          for {key, value} <- with({:env, env} <- List.keyfind(opts, :env, 0), do: env) || [],
              do: {to_string(key), if(value in [false, nil], do: nil, else: to_string(value))}

        TestIsolation.env!(declared)
        Port.open(name, opts)
    end
  end

  defp session_for(nil), do: nil

  defp session_for(cd) do
    case TestSandboxPreflight.session_ancestor(cd) do
      nil -> nil
      session -> {session, to_string(cd)}
    end
  end

  defp check!(session, cd) do
    root = TestIsolation.sandbox_root()
    real = TestSandboxPreflight.canonical(session)
    recorded = :persistent_term.get(@recorded, %{}) |> Map.get(real)

    unless TestSandboxPreflight.inside?(real, root),
      do: refuse!("#{session} is outside the sandbox #{root}")

    url = session |> File.read!() |> JSON.decode!() |> Map.get("url")

    unless is_binary(url) and URI.parse(url).host in ["127.0.0.1", "::1", "localhost"],
      do: refuse!("#{session} names #{inspect(url)}, not a loopback address")

    unless is_binary(recorded) and url == recorded,
      do:
        refuse!(
          "#{session} names #{inspect(url)}, not the fixture gateway this test " <>
            "recorded for it (#{inspect(recorded)})"
        )

    real_cd = TestSandboxPreflight.canonical(cd)

    unless TestSandboxPreflight.inside?(real_cd, root) or
             TestSandboxPreflight.inside?(real_cd, TestIsolation.repo()),
           do: refuse!("#{cd} is neither the repository nor the sandbox")
  end

  defp refuse!(message),
    do: raise(TestIsolation.Refusal, message: "refusing to launch: #{message} (wi_34a7be66)")
end
