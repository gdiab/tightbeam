defmodule Tightbeam.DevicesTest do
  use Tightbeam.TestCase, async: false

  alias Tightbeam.{DB, Devices, PairingAdmission, Schema, TestDevices}

  setup do
    name = :"db_#{System.unique_integer([:positive])}"
    start_supervised!({DB, path: ":memory:", name: name})
    :ok = Schema.ensure_all(name)
    admission = :"admission_#{System.unique_integer([:positive])}"
    start_supervised!({PairingAdmission, name: admission})
    %{db: name, admission: admission}
  end

  defp admin_device(db), do: TestDevices.paired!(db, "george", admin: true, device_id: "iphone")

  defp rows(db) do
    for table <- ~w(users devices device_versions) do
      {:ok, rows} = DB.query(db, "SELECT * FROM #{table} ORDER BY 1")
      {table, rows}
    end
  end

  test "the shared cold-start rule makes a directly added first user admin", %{db: db} do
    assert %{user_id: "installer", is_admin: true} =
             Devices.add_user(db, "installer", false)

    assert %{user_id: "guest", is_admin: false} = Devices.add_user(db, "guest", false)
  end

  # Stage 1: the freeze, its hatch and pending approval (core A K4a/K7/K8) are gone;
  # pairing is one-time-code only (covered in device_lifecycle_test.exs). This smoke
  # test keeps the old "approve overrides the claimed user, admin through the join"
  # subject: the code's target user wins over the claimed name.
  test "an uncoded pair creates nothing; a coded one pairs to the code's user", ctx do
    admin = admin_device(ctx.db)
    before = rows(ctx.db)

    assert {:refused, "pairing_code_required", _message} =
             Devices.pair(
               ctx.db,
               %{device_id: "dev-2", claimed_name: "Typo Name", platform: "ios", model: "iPhone"},
               admission: ctx.admission
             )

    assert rows(ctx.db) == before

    {code, %{user_id: "george"}} = TestDevices.issue_code!(ctx.db, admin)

    assert {:paired, %{device_id: "dev-2", user_id: "george", token: "tbt_" <> _ = token}} =
             TestDevices.coded_pair(ctx.db, "dev-2", "Typo Name", code, ctx.admission)

    assert %{device_id: "dev-2", user_id: "george", is_admin: true} =
             Devices.by_token(ctx.db, token)
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
