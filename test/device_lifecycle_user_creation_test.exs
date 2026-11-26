defmodule Tightbeam.DeviceLifecycleUserCreationTest do
  @moduledoc """
  Stage 1 (stage1-v12) S5.1 and §6.2: legacy pending devices denied at the migration
  and listed in the install receipt (P15, P16), and user creation only by gated,
  audited paths (P17, R-a, R-c), on an isolated in-memory database. P15 runs on a
  file-backed base: the migration is killed mid-transaction in its own OS process, then
  the base is reopened, migrated again and restarted, each in a fresh process.
  """

  use Tightbeam.TestCase, async: false

  alias Tightbeam.{
    DB,
    DeviceLifecycle,
    Devices,
    Escalation,
    EventLog,
    Model,
    Org,
    PairingAdmission,
    Schema,
    TestDevices,
    UserAdmin
  }

  @absent "/nonexistent/tightbeam-test/pairing-unfreeze"
  @denial "legacy_pending_device_denied"
  # 2025-10-28T22:20:26Z
  @t0 1_761_690_026_000
  @markup "<b>Mal</b> [link](http://e.test)\nnext"
  @long String.duplicate("n", 70)

  setup do
    db = :"user_creation_#{System.unique_integer([:positive])}"
    start_supervised!({DB, path: ":memory:", name: db})
    :ok = Schema.ensure_all(db)
    admission = :"user_creation_admission_#{System.unique_integer([:positive])}"
    start_supervised!({PairingAdmission, name: admission})
    on_exit(fn -> Application.put_env(:tightbeam, :pairing_unfreeze_path, @absent) end)

    Map.merge(%{db: db, admission: admission}, seed!(db))
  end

  # Two allowlisted devices with tokens (george an admin) and a session that can raise
  # a decision.
  defp seed!(db) do
    george = TestDevices.paired!(db, "george", admin: true, device_id: "iphone")
    guest = TestDevices.paired!(db, "guest", device_id: "guest-phone")

    raiser =
      Org.create(db, %{
        session_key: "agent:raiser:app",
        display_name: "raiser",
        owner_user_id: "george",
        origin: "user:george",
        archetype: "default",
        host: "testhost",
        harness: "claude",
        provider: "anthropic",
        model: Model.new("fable")
      })

    %{george: george, guest: guest, raiser: raiser}
  end

  defp read(db, sql, params \\ []) do
    {:ok, rows} = DB.query(db, sql, params)
    rows
  end

  defp devices(db),
    do:
      read(
        db,
        "SELECT deviceId, userId, claimedName, status, token, platform, model, createdAt FROM devices ORDER BY 1"
      )

  defp denials(db) do
    db
    |> EventLog.lifecycle_events()
    |> Enum.filter(&(&1.kind == @denial))
  end

  defp user_count(db), do: hd(hd(read(db, "SELECT COUNT(*) FROM users")))

  # A pending row as uncoded pairing left them before stage 1, with the fields given.
  defp legacy_pending!(db, device_id, user_id, name, platform, model, created_at) do
    # The claim slugs to the row's user, creating it as uncoded pairing did.
    {:pending, %{user_id: ^user_id}} =
      TestDevices.pair(db, %{device_id: device_id, claimed_name: user_id})

    read(
      db,
      """
      UPDATE devices SET claimedName = ?2, platform = ?3, model = ?4, createdAt = ?5
      WHERE deviceId = ?1
      """,
      [device_id, name, platform, model, created_at]
    )
  end

  # The P15 fixture: pending rows under a user created by pairing and under the
  # existing admin, one with platform and model empty, one holding markup, one too
  # long; allowlisted devices with tokens, a denied row and a decision.
  defp legacy_fixture!(ctx) do
    db = ctx.db
    legacy_pending!(db, "roci-a", "roci-on-example", "Roci on example", "linux", "", @t0)

    legacy_pending!(
      db,
      "roci-b",
      "roci-on-example",
      "Roci on example",
      "linux",
      "x86_64",
      @t0 + 1_000_000
    )

    legacy_pending!(db, "george-claim", "george", "George", "ios", "iPhone", @t0 + 500_000)
    legacy_pending!(db, "george-markup", "george", @markup, "", "", @t0 - 1_000_000)
    legacy_pending!(db, "george-long", "george", @long, nil, nil, @t0 + 2_000_000)

    {:pending, _} = TestDevices.pair(db, %{device_id: "old-denied", claimed_name: "Old"})
    :ok = Devices.deny(db, "old-denied")

    Escalation.operator_ask(db, %{
      verb: "operator-ask",
      origin: "agent:raiser",
      principal: {:session, ctx.raiser.session_key},
      transport_session_key: ctx.raiser.session_key,
      params: %{question: "a decision the migration must not touch?"}
    })

    assert [_] = read(db, "SELECT id FROM decision_requests")
  end

  # Return the database to its shape before stage 1, as the installed base has it.
  defp to_pre_stage1!(db) do
    for sql <- [
          "DROP TABLE device_lifecycle_migration",
          "DROP TABLE recovery_secrets",
          "DROP INDEX pairing_codes_outstanding",
          "DROP TABLE pairing_codes",
          "DROP TABLE gateway_host_actions",
          "ALTER TABLE devices DROP COLUMN tokenDelivered",
          "ALTER TABLE devices DROP COLUMN deliveryDeadline",
          "ALTER TABLE devices DROP COLUMN tokenGeneration",
          "ALTER TABLE devices DROP COLUMN pairedCodeId"
        ] do
      assert {:ok, _} = DB.query(db, sql)
    end
  end

  defp history(db) do
    %{
      users: read(db, "SELECT * FROM users ORDER BY 1"),
      decisions: read(db, "SELECT * FROM decision_requests ORDER BY 1"),
      devices: devices(db)
    }
  end

  @pending ~w(george-claim george-long george-markup roci-a roci-b)

  ## P15

  # One run of test/support/legacy_denial_runtime.exs: its own OS process and BEAM,
  # the real database owner on the file-backed base. The child halts when this Port
  # closes (its standard input reaches EOF), so it cannot outlive the test process
  # that owns the Port, whether the test passes, fails or times out; nothing here
  # signals a process by a remembered pid. Every line the child prints is appended to
  # `log`, which the test prints if it ends without finishing (P15's on_exit).
  defp launch(plan, args) do
    env =
      Enum.map(plan.env, fn {k, v} -> {to_charlist(k), if(v, do: to_charlist(v), else: false)} end)

    Port.open({:spawn_executable, plan.executable}, [
      :binary,
      :exit_status,
      :stderr_to_stdout,
      {:line, 8192},
      args: plan.args ++ args,
      env: env
    ])
  end

  defp await_line(port, log, pattern) do
    receive do
      {^port, {:data, {:eol, line}}} ->
        File.write!(log, line <> "\n", [:append])

        case Regex.run(pattern, line) do
          nil -> await_line(port, log, pattern)
          match -> match
        end

      {^port, {:data, {:noeol, part}}} ->
        File.write!(log, part, [:append])
        await_line(port, log, pattern)

      {^port, {:exit_status, status}} ->
        flunk("subprocess exited #{status} before #{inspect(pattern)}:\n" <> File.read!(log))
    after
      120_000 -> flunk("no #{inspect(pattern)} within 120 s:\n" <> File.read!(log))
    end
  end

  # The rest of the child's output, then its exit status.
  defp await_exit(port, log) do
    receive do
      {^port, {:data, {:eol, line}}} ->
        File.write!(log, line <> "\n", [:append])
        await_exit(port, log)

      {^port, {:data, {:noeol, part}}} ->
        File.write!(log, part, [:append])
        await_exit(port, log)

      {^port, {:exit_status, status}} ->
        status
    after
      120_000 -> flunk("subprocess did not exit within 120 s:\n" <> File.read!(log))
    end
  end

  defp run!(plan, log, mode, expected) do
    port = launch(plan, [mode])
    await_line(port, log, ~r/\A#{expected}\z/)
    status = await_exit(port, log)
    assert status == 0, "#{mode} exited #{status}:\n" <> File.read!(log)
  end

  defp open_base!(plan, id) do
    db = :"p15_#{id}_#{System.unique_integer([:positive])}"

    start_supervised!(
      Supervisor.child_spec(
        {DB,
         path: Path.join(plan.base, "state.db"),
         name: db,
         guard_inputs: [],
         payload_root: plan.payload,
         base_lock: false},
        id: db
      )
    )

    db
  end

  defp denial_count(db),
    do: hd(hd(read(db, "SELECT COUNT(*) FROM lifecycle_events WHERE kind = ?1", [@denial])))

  # The sibling CLI test's bound: several fresh BEAMs, each running the boot schema.
  @tag :tmp_dir
  @tag timeout: 600_000
  test "P15: a migration killed mid-transaction leaves nothing; the rerun denies once, the restart adds nothing",
       %{tmp_dir: tmp} do
    plan = Tightbeam.GuardRuntimeFixture.prepare!(tmp, "legacy_denial_runtime.exs")
    File.mkdir_p!(plan.base)

    # Every subprocess line, printed if the test ends without finishing: a failed
    # assertion, a helper's own timeout or ExUnit's.
    log = Path.join(tmp, "p15-subprocess.log")
    done = Path.join(tmp, "p15-finished")
    File.write!(log, "")

    on_exit(fn ->
      unless File.exists?(done) do
        output =
          case File.read(log) do
            {:ok, contents} -> contents
            {:error, reason} -> "(subprocess log unreadable: #{inspect(reason)})"
          end

        IO.puts("P15 did not finish; subprocess output:\n" <> output)
      end
    end)

    # The fixture, on a file-backed base returned to its shape before stage 1.
    db = open_base!(plan, "seed")
    :ok = Schema.ensure_all(db)
    seeded = Map.put(seed!(db), :db, db)
    legacy_fixture!(seeded)
    to_pre_stage1!(db)
    before = history(db)
    alerts_before = read(db, "SELECT * FROM owner_alerts ORDER BY 1")
    stop_supervised!(db)

    # A gateway database life runs the migration, which its own temporary trigger holds
    # inside the transaction at the third denial write; it is killed (SIGKILL) there,
    # after two denial writes and before any commit.
    # The only signal in this test: the child's own BEAM pid, while its Port is open
    # and no exit of it has been reported, and the stall holds it inside its transaction.
    port = launch(plan, ["migrate-stalled"])
    [_, os_pid] = await_line(port, log, ~r/\Apid (\d+)\z/)
    await_line(port, log, ~r/\Adenial 3 /)

    receive do
      {^port, {:exit_status, status}} ->
        flunk("stalled migration exited #{status}:\n" <> File.read!(log))
    after
      0 -> assert {_, 0} = System.cmd("kill", ["-KILL", os_pid])
    end

    assert await_exit(port, log) != 0

    # Reopened: neither the S5 records nor any denial survived.
    db = open_base!(plan, "after_kill")

    assert read(db, "SELECT name FROM sqlite_master WHERE name = 'device_lifecycle_migration'") ==
             []

    assert read(db, "SELECT name FROM sqlite_master WHERE name = 'pairing_codes'") == []
    assert denial_count(db) == 0
    assert history(db) == before
    stop_supervised!(db)

    # The rerun, in a fresh gateway database life, denies every legacy pending row.
    run!(plan, log, "migrate", "migrate: ok")
    db = open_base!(plan, "after_rerun")
    assert_denied!(db, seeded, before, alerts_before)
    stop_supervised!(db)

    # A gateway restart (boot schema and boot observation) writes no further denial.
    run!(plan, log, "boot", "boot: ok")
    db = open_base!(plan, "after_restart")
    assert denial_count(db) == length(@pending)
    assert read(db, "SELECT COUNT(*) FROM devices WHERE status = 'pending'") == [[0]]
    assert read(db, "SELECT * FROM owner_alerts ORDER BY 1") == alerts_before
    File.write!(done, "")
  end

  defp assert_denied!(db, seeded, before, alerts_before) do
    # No pending rows; each former pending row is denied, token cleared, nothing else.
    assert read(db, "SELECT COUNT(*) FROM devices WHERE status = 'pending'") == [[0]]

    expected =
      Enum.map(before.devices, fn
        [id, user, name, "pending", _token, platform, model, created] ->
          assert id in @pending
          [id, user, name, "denied", nil, platform, model, created]

        row ->
          row
      end)

    assert devices(db) == expected
    assert history(db).users == before.users
    assert history(db).decisions == before.decisions

    # Each allowlisted token still authenticates.
    for device <- [seeded.george, seeded.guest] do
      assert Devices.by_token(db, device.token).device_id == device.device_id
      assert :ok = DeviceLifecycle.sign_in(db, device.token)
    end

    # Exactly one denial record per former pending row, naming what S5.1 lists.
    records = denials(db)
    assert Enum.sort(Enum.map(records, & &1.subject)) == @pending

    by_id = Map.new(before.devices, fn [id | _] = row -> {id, row} end)

    for %{subject: id, detail: detail} <- records do
      [_id, user, name, "pending", _token, platform, model, created] = Map.fetch!(by_id, id)
      denial = JSON.decode!(detail)

      assert %{
               "deviceId" => ^id,
               "userId" => ^user,
               "claimedName" => ^name,
               "networkOrigin" => "not recorded",
               "createdAt" => ^created,
               "actor" => "stage1-migration",
               "deniedAt" => denied_at
             } = denial

      assert is_integer(denied_at)

      assert denial["clientReported"] == %{
               "platform" => if(platform in [nil, ""], do: "not recorded", else: platform),
               "model" => if(model in [nil, ""], do: "not recorded", else: model)
             }

      # No platform or model value appears in the origin field.
      refute denial["networkOrigin"] in ["linux", "ios", "iPhone", "x86_64"]
    end

    # The migration sends no per-row alert.
    assert read(db, "SELECT * FROM owner_alerts ORDER BY 1") == alerts_before
  end

  ## P16

  test "P16: the install receipt lists the denials in order; denied rows re-pair only by code",
       ctx do
    db = ctx.db
    legacy_fixture!(ctx)
    to_pre_stage1!(db)
    :ok = DeviceLifecycle.ensure_schema(db)

    escaped = "<b>Mal</b> [link](http://e.test)\\u000Anext"
    long = String.duplicate("n", 64)

    assert DeviceLifecycle.legacy_denial_receipt(db) ==
             Enum.join(
               [
                 "5 legacy pending devices denied",
                 "george | #{escaped} | origin: not recorded | client-reported: platform not recorded, model not recorded | 2025-10-28T22:03:46Z",
                 "george | George | origin: not recorded | client-reported: platform ios, model iPhone | 2025-10-28T22:28:46Z",
                 "george | #{long} | origin: not recorded | client-reported: platform not recorded, model not recorded | 2025-10-28T22:53:46Z",
                 "roci-on-example | Roci on example | origin: not recorded | client-reported: platform linux, model not recorded | 2025-10-28T22:20:26Z",
                 "roci-on-example | Roci on example | origin: not recorded | client-reported: platform linux, model x86_64 | 2025-10-28T22:37:06Z"
               ],
               "\n"
             )

    # A database with no pending rows at the migration: "none".
    empty = :"user_creation_empty_#{System.unique_integer([:positive])}"
    start_supervised!(%{id: empty, start: {DB, :start_link, [[path: ":memory:", name: empty]]}})
    :ok = Schema.ensure_all(empty)
    assert DeviceLifecycle.legacy_denial_receipt(empty) == "Legacy pending devices denied: none"

    # A coded pairing of a denied id: paired and allowlisted for the code's user.
    {code, _} = TestDevices.issue_code!(db, ctx.george, "guest")

    assert {:paired, %{user_id: "guest"}} =
             TestDevices.coded_pair(db, "roci-a", "Roci", code, ctx.admission)

    assert %{status: "allowlisted", user_id: "guest"} = Devices.by_id(db, "roci-a")

    # An uncoded pairing of another: refused, and the row stays denied.
    assert {:refused, "pairing_code_required", _} =
             Devices.pair(db, %{device_id: "roci-b", claimed_name: "Roci on example"},
               admission: ctx.admission
             )

    assert %{status: "denied"} = Devices.by_id(db, "roci-b")
  end

  ## P17

  test "P17: approve-device naming a new user creates it at code issue, audited; pairing never",
       ctx do
    db = ctx.db
    users_before = user_count(db)

    # Gated: a non-admin device, a session and the org credential are refused, and
    # no user is created.
    non_admin = TestDevices.device_call(ctx.guest, %{verb: "approve-device", params: %{}})
    assert %{code: "forbidden"} = DeviceLifecycle.issue_code(db, non_admin, "newbie")

    for call <- [
          %{
            verb: "approve-device",
            origin: "agent:x",
            principal: {:session, "x"},
            auth_class: "session",
            params: %{}
          },
          %{
            verb: "approve-device",
            origin: "user:george",
            principal: {:user, "george"},
            auth_class: "org",
            params: %{}
          }
        ] do
      assert %{code: code} = DeviceLifecycle.issue_code(db, call, "newbie")
      assert code in ["forbidden", "user_authentication_required"]
    end

    assert Devices.user(db, "newbie") == nil
    assert user_count(db) == users_before
    refute_received {:tightbeam_ephemeral, _}

    # The user and its creation record are written in the command's own transaction:
    # when the code cannot be stored, neither exists.
    read(db, """
    CREATE TRIGGER p17_fail BEFORE INSERT ON pairing_codes
    BEGIN SELECT RAISE(ABORT, 'p17 code store failed'); END
    """)

    assert catch_error(DeviceLifecycle.issue_code(db, admin_call(ctx), "newbie"))
    read(db, "DROP TRIGGER p17_fail")
    assert Devices.user(db, "newbie") == nil
    assert read(db, "SELECT COUNT(*) FROM lifecycle_events WHERE kind = 'user_created'") == [[0]]

    # From an admin device: created at code issue, non-admin, with an accepted
    # creation record naming the issuing device.
    {code, record} = TestDevices.issue_code!(db, ctx.george, "newbie")
    assert record.user_id == "newbie"
    assert %{is_admin: false, removed_at: nil} = Devices.user(db, "newbie")
    assert user_count(db) == users_before + 1

    newbie = Enum.find(UserAdmin.list(db), &(&1["userId"] == "newbie"))

    assert %{
             "via" => "approve-device",
             "issuingDeviceId" => "iphone",
             "issuingUserId" => "george"
           } = newbie["creation"]

    refute Map.has_key?(newbie, "creationNote")

    # A second code for the now-existing user creates nothing more.
    {code2, _} = TestDevices.issue_code!(db, ctx.george, "newbie")
    assert read(db, "SELECT COUNT(*) FROM lifecycle_events WHERE kind = 'user_created'") == [[1]]

    # The coded pairing allowlists the device for the code's user and adds no user.
    users_issued = user_count(db)

    assert {:paired, %{user_id: "newbie"}} =
             TestDevices.coded_pair(db, "newbie-phone", "Phone", code, ctx.admission)

    assert user_count(db) == users_issued

    # Names that slug to an absent user or to an existing one: filed under the code's
    # user only, coded or not, and no pairing adds a users row.
    assert {:paired, %{user_id: "newbie"}} =
             TestDevices.coded_pair(db, "absent-name", "Nobody Here", code2, ctx.admission)

    {code3, _} = TestDevices.issue_code!(db, ctx.george, "guest")

    assert {:paired, %{user_id: "guest"}} =
             TestDevices.coded_pair(db, "george-name", "George", code3, ctx.admission)

    for {id, name} <- [{"uncoded-absent", "Nobody Here"}, {"uncoded-george", "George"}] do
      assert {:refused, "pairing_code_required", _} =
               Devices.pair(db, %{device_id: id, claimed_name: name}, admission: ctx.admission)

      assert Devices.by_id(db, id) == nil
    end

    assert Devices.user(db, "nobody-here") == nil
    assert user_count(db) == users_issued
    assert %{user_id: "newbie"} = Devices.by_id(db, "absent-name")
    assert %{user_id: "guest"} = Devices.by_id(db, "george-name")
  end

  test "R-c: a removed user's id is not recreated by approve-device", ctx do
    db = ctx.db
    read(db, "UPDATE users SET removedAt = 1, removedBy = 'user:george' WHERE userId = 'guest'")

    assert %{code: "user_removed"} =
             DeviceLifecycle.issue_code(db, admin_call(ctx), "guest")

    assert read(db, "SELECT COUNT(*) FROM lifecycle_events WHERE kind = 'user_created'") == [[0]]
    refute_received {:tightbeam_ephemeral, _}
  end

  test "the code and creation writers are reachable only through the gated command" do
    exported = DeviceLifecycle.__info__(:functions)
    refute {:insert_code_in_txn, 9} in exported
    refute {:enroll_in_txn, 5} in exported
    refute {:code_user_in_txn, 2} in exported
    refute {:user_created_in_txn, 6} in exported
  end

  defp admin_call(ctx),
    do: TestDevices.device_call(ctx.george, %{verb: "approve-device", params: %{}})
end
