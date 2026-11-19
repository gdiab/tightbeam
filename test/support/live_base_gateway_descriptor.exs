import ExUnit.Assertions
alias Tightbeam.Gateway

Tightbeam.GuardGatewayFixture.run!(fn %{config: config, base: base} ->
  # R5: the pid, command, and start time form the stop identity, rewritten every
  # boot; the cli token survives a reboot.
  Gateway.children(config)
  first = base |> Path.join("gateway.json") |> File.read!() |> JSON.decode!()

  assert first["ownedPid"] == System.pid()
  assert is_binary(first["ownedCommand"]) and first["ownedCommand"] != ""
  assert is_binary(first["ownedStart"]) and first["ownedStart"] != ""

  Gateway.children(config)
  second = base |> Path.join("gateway.json") |> File.read!() |> JSON.decode!()

  assert second["ownedPid"] == System.pid()
  assert second["cliToken"] == first["cliToken"]
end)

IO.puts("guarded-gateway-descriptor: ok")
