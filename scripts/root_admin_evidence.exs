# Stage 1 P5c-H support (stage1-v12 P5c-H, F1 erratum 1 rev 4 §1c.2). Run only by
# .github/workflows/root-admin-evidence.yml on a disposable GitHub-hosted runner,
# outside every suite, with MIX_ENV=test:
#
#   mix run scripts/root_admin_evidence.exs prepare <root>
#     An admitted throwaway base at <root>/base: the gateway's own database start and
#     schema create and migrate state.db; it holds one admin user, george, with a Main
#     session, and names george as the owner-alert user. No gateway runs afterwards.
#   mix run scripts/root_admin_evidence.exs observe <root>
#     The gateway's boot observation (DeviceLifecycle.observe_at_boot/2) on that base:
#     the next-start alert and Main wake for each recorded root action. Run as the
#     database's owner.
#
# It launches nothing and needs no privilege; the workflow does every account and
# sudo step itself.

alias Tightbeam.{DB, DeviceLifecycle, Model, Org, Schema}

start_db! = fn root ->
  {:ok, db} =
    DB.start_link(
      path: Path.join([root, "base", "state.db"]),
      name: nil,
      guard_inputs: [],
      payload_root: Path.join(root, "tightbeam")
    )

  db
end

case System.argv() do
  ["prepare", root] ->
    File.mkdir_p!(root)
    %{base: base} = Tightbeam.GuardRuntimeFixture.prepare!(root, "unused")
    File.mkdir_p!(base)
    db = start_db!.(root)
    :ok = Schema.ensure_all(db)

    _george =
      Tightbeam.TestDevices.paired!(db, "george", admin: true, device_id: "evidence-device")

    Org.create(db, %{
      session_key: Org.personal_session_key("george"),
      display_name: "Main",
      kind: "main",
      is_built_in: true,
      owner_user_id: "george",
      origin: "user:george",
      archetype: "default",
      host: "evidence-host",
      harness: "claude",
      provider: "anthropic",
      model: Model.new("fable")
    })

    :ok = Org.put_setting(db, "owner-alerts-user", "george")
    GenServer.stop(db)
    IO.puts("prepared #{base}")

  ["observe", root] ->
    db = start_db!.(root)
    :ok = DeviceLifecycle.observe_at_boot(db, "/nonexistent/tightbeam-evidence/pairing-unfreeze")
    GenServer.stop(db)
    IO.puts("observed")

  other ->
    IO.puts(:stderr, "usage: prepare <root> | observe <root> (got #{inspect(other)})")
    System.halt(64)
end
