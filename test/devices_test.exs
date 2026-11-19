defmodule Tightbeam.DevicesTest do
  use Tightbeam.TestCase, async: false

  alias Tightbeam.{DB, Devices, PairingFreeze, Schema, TestDevices}

  setup do
    name = :"db_#{System.unique_integer([:positive])}"
    start_supervised!({DB, path: ":memory:", name: name})
    :ok = Schema.ensure_all(name)
    frozen = Application.get_env(:tightbeam, :pairing_unfreeze_path)
    on_exit(fn -> Application.put_env(:tightbeam, :pairing_unfreeze_path, frozen) end)
    %{db: name}
  end

  defp pair(db, device_id, claimed_name) do
    Devices.pair(db, %{
      device_id: device_id,
      claimed_name: claimed_name,
      platform: "ios",
      model: "iPhone"
    })
  end

  # Lift the freeze with a file that passes every C6a check: an existing regular
  # file owned by root and not writable by group or others, whose directory and
  # that directory's parent are root-owned and not group- or other-writable.
  defp lift! do
    path =
      Enum.find(["/usr/bin/env", "/bin/sh", "/usr/bin/true"], &PairingFreeze.read(&1).lifted) ||
        flunk("this host offers no root-owned fixture file for a valid unfreeze file")

    Application.put_env(:tightbeam, :pairing_unfreeze_path, path)
    path
  end

  defp freeze!,
    do:
      Application.put_env(
        :tightbeam,
        :pairing_unfreeze_path,
        "/nonexistent/tightbeam-test/pairing-unfreeze"
      )

  defp admin_device(db), do: TestDevices.paired!(db, "george", admin: true, device_id: "iphone")

  defp approve(db, device_id, admin) do
    Devices.approve_with_firehose(
      db,
      device_id,
      nil,
      TestDevices.device_call(admin, %{verb: "approve-device", params: %{device_id: device_id}})
    )
  end

  defp collected(db, device_id) do
    {:ok, [[value]]} =
      DB.query(db, "SELECT tokenCollected FROM devices WHERE deviceId = ?1", [device_id])

    value
  end

  defp rows(db) do
    for table <- ~w(users devices device_versions) do
      {:ok, rows} = DB.query(db, "SELECT * FROM #{table} ORDER BY 1")
      {table, rows}
    end
  end

  # K7: while frozen every pair_request is refused and no row is created or changed.
  test "frozen: every pair_request gets pairing_frozen and changes nothing", %{db: db} do
    admin = admin_device(db)
    revoked = TestDevices.paired!(db, "george", device_id: "revoked")
    :ok = Devices.revoke(db, revoked.device_id)
    {:pending, _} = TestDevices.pair(db, %{device_id: "pending", claimed_name: "Visitor"})
    {:pending, _} = TestDevices.pair(db, %{device_id: "denied", claimed_name: "Stranger"})
    :ok = Devices.deny(db, "denied")
    before = rows(db)

    for {device_id, name} <- [
          {admin.device_id, "George"},
          {"revoked", "George"},
          {"pending", "Visitor"},
          {"denied", "Stranger"},
          {"unknown", "Someone"}
        ] do
      assert {:refused, "pairing_frozen"} = pair(db, device_id, name)
    end

    assert rows(db) == before
    assert Devices.by_token(db, admin.token).device_id == admin.device_id
  end

  # K4a: the cold start is frozen, lift or not; nothing is created either way.
  test "the cold start creates nothing, frozen or lifted", %{db: db} do
    assert {:refused, "pairing_frozen"} = pair(db, "first", "George")
    assert rows(db) == [{"users", []}, {"devices", []}, {"device_versions", []}]

    lift!()
    assert {:refused, "pairing_frozen"} = pair(db, "first", "George")
    assert rows(db) == [{"users", []}, {"devices", []}, {"device_versions", []}]
  end

  test "the shared cold-start rule makes a directly added first user admin", %{db: db} do
    assert %{user_id: "installer", is_admin: true} =
             Devices.add_user(db, "installer", false)

    assert %{user_id: "guest", is_admin: false} = Devices.add_user(db, "guest", false)
  end

  # K8a (1), (2): lifted, a new device goes pending, an admin device approves it,
  # and it collects its token exactly once.
  test "lifted: a new device pairs, is approved, and collects its token once", %{db: db} do
    admin = admin_device(db)
    lift!()

    assert {:pending, %{token: nil, user_id: "visitor"}} = pair(db, "ipad", "Visitor")
    assert {:pending, _} = pair(db, "ipad", "Visitor")

    approved = approve(db, "ipad", admin)
    assert %{status: "allowlisted", token: "tbt_" <> _ = token} = approved
    assert collected(db, "ipad") == 0

    assert {:paired, %{token: ^token}} = pair(db, "ipad", "Visitor")
    assert collected(db, "ipad") == 1
    assert {:refused, "already_paired"} = pair(db, "ipad", "Visitor")
    assert Devices.by_token(db, token).device_id == "ipad"
  end

  # K8a (3): a token that existed before installation counts as collected.
  test "lifted: an existing token holder gets already_paired and keeps its token", %{db: db} do
    admin = admin_device(db)
    lift!()
    before = rows(db)

    assert {:refused, "already_paired"} = pair(db, admin.device_id, "George")
    assert rows(db) == before
    assert Devices.by_token(db, admin.token).device_id == admin.device_id
  end

  # K8a (4): a revoked device is never re-minted; it returns to pending.
  test "lifted: a revoked device goes pending without a token", %{db: db} do
    _admin = admin_device(db)
    revoked = TestDevices.paired!(db, "george", device_id: "old-ipad")
    :ok = Devices.revoke(db, revoked.device_id)
    lift!()

    assert {:pending, %{status: "pending", token: nil}} = pair(db, "old-ipad", "George")
    assert %{status: "pending", token: nil} = Devices.by_id(db, "old-ipad")
  end

  test "approve-device is refused while frozen and for a device that is not pending",
       %{db: db} do
    admin = admin_device(db)
    {:pending, _} = TestDevices.pair(db, %{device_id: "ipad", claimed_name: "Visitor"})
    before = rows(db)

    assert %{code: "pairing_frozen", message: message} = approve(db, "ipad", admin)
    assert message == PairingFreeze.frozen_message()
    assert rows(db) == before

    lift!()
    assert %{code: "device_not_pending"} = approve(db, admin.device_id, admin)
    assert Devices.by_token(db, admin.token).device_id == admin.device_id
  end

  # K8b: the token is marked collected in the pairing transaction, so a response
  # lost after that commit strands the device; George revokes it and approves again.
  test "lifted: a lost collection response is recovered by revoke and approval", %{db: db} do
    admin = admin_device(db)
    lift!()

    {:pending, _} = pair(db, "ipad", "Visitor")
    approved = approve(db, "ipad", admin)

    # The collecting request commits; its response never reaches the device.
    assert {:paired, %{token: orphan}} = pair(db, "ipad", "Visitor")
    assert orphan == approved.token
    assert {:refused, "already_paired"} = pair(db, "ipad", "Visitor")

    revoke_call =
      TestDevices.device_call(admin, %{verb: "revoke-device", params: %{device_id: "ipad"}})

    assert :ok = Devices.revoke_with_firehose(db, "ipad", revoke_call)
    assert Devices.by_token(db, orphan) == nil
    assert %{token: nil} = Devices.by_id(db, "ipad")

    assert {:pending, _} = pair(db, "ipad", "Visitor")
    reapproved = approve(db, "ipad", admin)
    assert {:paired, %{token: token}} = pair(db, "ipad", "Visitor")
    assert token == reapproved.token
    refute token == orphan
    assert Devices.by_token(db, token).device_id == "ipad"
    assert {:refused, "already_paired"} = pair(db, "ipad", "Visitor")
  end

  test "approve can override the claimed user and derives admin through the join", %{db: db} do
    admin = admin_device(db)
    lift!()
    {:pending, _} = pair(db, "dev-2", "Typo Name")

    approved =
      Devices.approve_with_firehose(
        db,
        "dev-2",
        "george",
        TestDevices.device_call(admin, %{verb: "approve-device", params: %{device_id: "dev-2"}})
      )

    assert approved.user_id == "george"
    assert approved.is_admin
    assert approved.status == "allowlisted"
    assert Devices.by_token(db, approved.token).is_admin
    freeze!()
  end

  test "revoke clears token while by_id remains allowlisted", %{db: db} do
    device = admin_device(db)
    assert :ok = Devices.revoke(db, device.device_id)
    assert Devices.by_token(db, device.token) == nil
    assert %{status: "allowlisted", token: nil} = Devices.by_id(db, device.device_id)
  end

  test "admin follows the user and unknown mutations raise", %{db: db} do
    phone = TestDevices.paired!(db, "flynn", device_id: "phone-1")
    tablet = TestDevices.paired!(db, "flynn", device_id: "phone-2")
    assert Devices.by_id(db, tablet.device_id).is_admin

    refute Devices.set_user_admin(db, "flynn", false).is_admin
    refute Devices.by_id(db, phone.device_id).is_admin

    assert_raise ArgumentError, "unknown device: missing", fn -> Devices.revoke(db, "missing") end

    assert_raise ArgumentError, "unknown user: missing", fn ->
      Devices.set_user_admin(db, "missing", true)
    end
  end
end
