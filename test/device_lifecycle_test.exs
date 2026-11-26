defmodule Tightbeam.DeviceLifecycleTest do
  @moduledoc """
  Stage 1 (stage1-v8) gateway side: one-time-code pairing, recovery enrolment,
  delivery by use, and the retired freeze. P1, P2, P3, P3b, P7, P7a, P8, P8a and P9,
  on an isolated in-memory database. The CLI ceremonies (P4–P6, P5b, P5c) are in
  `device_recovery_cli_test.exs`.
  """

  use Tightbeam.TestCase, async: false

  alias Tightbeam.{
    DB,
    DeviceLifecycle,
    Devices,
    EventLog,
    Model,
    Native,
    Org,
    OwnerAlerts,
    PairingAdmission,
    Schema,
    TestDevices
  }

  @absent "/nonexistent/tightbeam-test/pairing-unfreeze"

  setup do
    db = :"lifecycle_#{System.unique_integer([:positive])}"
    start_supervised!({DB, path: ":memory:", name: db})
    :ok = Schema.ensure_all(db)
    admission = :"admission_#{System.unique_integer([:positive])}"
    start_supervised!({PairingAdmission, name: admission})
    on_exit(fn -> Application.put_env(:tightbeam, :pairing_unfreeze_path, @absent) end)

    george = TestDevices.paired!(db, "george", admin: true, device_id: "iphone")
    guest = TestDevices.paired!(db, "guest", device_id: "guest-phone")

    # Display names are unique across the organization (option-2 base): one per user.
    for user <- ["george", "guest"] do
      Org.create(db, %{
        session_key: Org.personal_session_key(user),
        display_name: "Main #{user}",
        kind: "main",
        is_built_in: true,
        owner_user_id: user,
        origin: "user:#{user}",
        archetype: "default",
        host: "testhost",
        harness: "claude",
        provider: "anthropic",
        model: Model.new("fable")
      })
    end

    :ok = Org.put_setting(db, "owner-alerts-user", "george")
    %{db: db, admission: admission, george: george, guest: guest}
  end

  defp lifecycle(db, kind), do: Enum.filter(EventLog.lifecycle_events(db), &(&1.kind == kind))

  defp alerts(db, kind) do
    {:ok, rows} = DB.query(db, "SELECT body FROM owner_alerts WHERE kind = ?1", [kind])
    Enum.map(rows, &hd/1)
  end

  defp rows(db) do
    for table <- ~w(users devices device_versions) do
      {:ok, rows} = DB.query(db, "SELECT * FROM #{table} ORDER BY 1")
      {table, rows}
    end
  end

  defp sign_in(db, token), do: DeviceLifecycle.sign_in(db, token)

  # Every text record a reader could see: transcripts, events, lifecycle, projections.
  defp all_records(db) do
    for table <- ~w(messages events lifecycle_events owner_alerts admin_projection_versions wakes),
        reduce: "" do
      acc ->
        case DB.query(db, "SELECT * FROM #{table}") do
          {:ok, rows} -> acc <> inspect(rows, limit: :infinity, printable_limit: :infinity)
          {:error, _} -> acc
        end
    end
  end

  ## P7: issuing and coded pairing

  test "P7: a code pairs a new device once; reuse, expiry, holders, uncoded, long names", ctx do
    db = ctx.db
    {code, record} = TestDevices.issue_code!(db, ctx.george)
    assert record.code_id =~ ~r/\Apc_[0-9a-f]{16}\z/
    assert record.user_id == "george"
    assert record.message =~ "pairing code #{record.code_id} issued for george, expires "

    # A new id pairs; the stored name has no code.
    assert {:paired, %{token: "tbt_" <> _ = token, user_id: "george"}} =
             TestDevices.coded_pair(db, "ipad", "iPad", code, ctx.admission)

    assert %{claimed_name: "iPad", status: "allowlisted"} = Devices.by_id(db, "ipad")
    assert :ok = sign_in(db, token)

    # The same code again, from the same or another id: invalid.
    for id <- ["ipad", "other"] do
      assert {:refused, "pairing_code_invalid", _} =
               TestDevices.coded_pair(db, id, "X", code, ctx.admission)
    end

    # A device that holds a token: already_paired, and the code stays usable.
    {code2, _} = TestDevices.issue_code!(db, ctx.george)

    assert {:refused, "already_paired", _} =
             TestDevices.coded_pair(db, "iphone", "iPhone", code2, ctx.admission)

    assert {:paired, _} = TestDevices.coded_pair(db, "mac", "Mac", code2, ctx.admission)

    # An expired code.
    {code3, record3} = TestDevices.issue_code!(db, ctx.george)

    {:ok, _} =
      DB.query(db, "UPDATE pairing_codes SET expiresAt = issuedAt + 1 WHERE codeId = ?1", [
        record3.code_id
      ])

    assert {:refused, "pairing_code_invalid", _} =
             TestDevices.coded_pair(db, "late", "Late", code3, ctx.admission)

    # Uncoded: refused, no row.
    before = rows(db)

    assert {:refused, "pairing_code_required", message} =
             Devices.pair(db, %{device_id: "nocode", claimed_name: "Just a name"},
               admission: ctx.admission
             )

    assert message =~ "/tightbeam approve-device"
    assert rows(db) == before

    # A name too long for the code: invalid, with the shorten message.
    {code4, _} = TestDevices.issue_code!(db, ctx.george)
    long = String.duplicate("n", 48)

    assert {:refused, "pairing_code_invalid", too_long} =
             TestDevices.coded_pair(db, "long", long, code4, ctx.admission)

    assert too_long =~ "46 characters"
    assert {:paired, _} = TestDevices.coded_pair(db, "short", "Short", code4, ctx.admission)

    # Codes match case-insensitively; a code for another user pairs as that user.
    {code5, _} = TestDevices.issue_code!(db, ctx.george, "guest")

    assert {:paired, %{user_id: "guest"}} =
             TestDevices.coded_pair(
               db,
               "guest-ipad",
               "iPad",
               String.downcase(code5),
               ctx.admission
             )
  end

  test "P7: only an admin-paired device issues a code", ctx do
    call = TestDevices.device_call(ctx.guest, %{verb: "approve-device", params: %{}})
    assert %{code: "forbidden"} = DeviceLifecycle.issue_code(ctx.db, call, nil)

    for call <- [
          %{
            verb: "approve-device",
            origin: "user:george",
            principal: {:user, "george"},
            params: %{}
          },
          %{
            verb: "approve-device",
            origin: "agent:x",
            principal: {:session, "x"},
            auth_class: "session",
            params: %{}
          }
        ] do
      assert %{code: "user_authentication_required"} =
               DeviceLifecycle.issue_code(ctx.db, call, nil)
    end

    refute_received {:tightbeam_ephemeral, _}
    assert {:ok, []} = DB.query(ctx.db, "SELECT codeId FROM pairing_codes")
  end

  test "P7a: an empty organization creates nothing; the local add-user shortcut is unchanged" do
    db = :"empty_#{System.unique_integer([:positive])}"
    start_supervised!(%{id: db, start: {DB, :start_link, [[path: ":memory:", name: db]]}})
    :ok = Schema.ensure_all(db)
    admission = :"empty_admission_#{System.unique_integer([:positive])}"

    start_supervised!(%{
      id: admission,
      start: {PairingAdmission, :start_link, [[name: admission]]}
    })

    assert {:refused, "pairing_code_required", _} =
             Devices.pair(db, %{device_id: "first", claimed_name: "George"}, admission: admission)

    assert {:refused, "pairing_code_invalid", _} =
             Devices.pair(db, %{device_id: "first", claimed_name: "George TB-AAAA-BBBB-CCCC"},
               admission: admission
             )

    for table <- ~w(users devices) do
      assert {:ok, []} = DB.query(db, "SELECT * FROM #{table}")
    end

    # The local shortcut itself is the CLI's (cli/src/users.rs), tested there.
  end

  ## P3, P3b: verifiers and records

  test "P3/P3b: only Argon2id verifiers are stored; 5 outstanding at most; no fragment anywhere",
       ctx do
    db = ctx.db

    issued =
      for _ <- 1..6 do
        {code, record} = TestDevices.issue_code!(db, ctx.george)
        Process.sleep(2)
        {code, record}
      end

    {:ok, stored} =
      DB.query(
        db,
        "SELECT codeId, verifier, salt, invalidatedAt FROM pairing_codes ORDER BY issuedAt"
      )

    assert length(stored) == 6
    [[oldest_id, _, _, invalidated] | rest] = stored
    assert is_integer(invalidated), "the oldest of six is invalidated"
    assert Enum.all?(rest, fn [_, _, _, inv] -> is_nil(inv) end)
    assert oldest_id == elem(hd(issued), 1).code_id

    salts = Enum.map(stored, fn [_, _, salt, _] -> salt end)
    assert Enum.all?(salts, &(byte_size(&1) == 16))
    assert length(Enum.uniq(salts)) == 6

    # Each verifier is exactly Argon2id(m=64 MiB, t=3, p=1, 32 bytes) of its code.
    for {{code, record}, [id, verifier, salt, _]} <- Enum.zip(issued, stored) do
      assert id == record.code_id
      assert verifier == Native.argon2id(code, salt)
    end

    # The oldest code no longer pairs; the others do.
    {oldest_code, _} = hd(issued)

    assert {:refused, "pairing_code_invalid", _} =
             TestDevices.coded_pair(db, "d0", "D", oldest_code, ctx.admission)

    # Enrol a secret too, then scan every record for any code, secret or fragment.
    call = TestDevices.device_call(ctx.george, %{verb: "recovery-enroll", params: %{}})
    assert %{user_id: "george"} = DeviceLifecycle.enroll(db, call)
    assert_received {:tightbeam_ephemeral, secret_text}
    [secret] = Regex.run(~r/TBR-[0-9A-Z-]{23}/, secret_text)

    records = all_records(db)

    for {code, _} <- issued,
        text <- [code, String.slice(code, 3, 9), String.slice(code, -9, 9)] do
      refute records =~ text, "a code or fragment leaked into a record"
    end

    for text <- [secret, String.slice(secret, 4, 11), String.slice(secret, -11, 11)] do
      refute records =~ text, "the secret or a fragment leaked into a record"
    end

    for [_, verifier, salt, _] <- stored do
      refute records =~ Base.encode16(verifier), "a verifier leaked"
      refute records =~ Base.encode16(salt, case: :lower)
    end

    # Records identify codes only by code id.
    assert Enum.all?(lifecycle(db, "pairing_code_issued"), &(&1.subject =~ ~r/\Apc_/))

    {time, _} = :timer.tc(fn -> Native.argon2id("TB-AAAA-BBBB-CCCC", <<0::128>>) end)
    assert time > 10_000, "one verifier check costs real work (#{time} µs)"
  end

  ## P2: enrolment

  test "P2: enrolment shows the secret once, stores its hash, alerts; re-enrol invalidates",
       ctx do
    db = ctx.db
    call = TestDevices.device_call(ctx.george, %{verb: "recovery-enroll", params: %{}})

    assert %{user_id: "george", message: message} = DeviceLifecycle.enroll(db, call)
    assert message =~ "recovery secret enrolled for george at "
    assert_received {:tightbeam_ephemeral, first_text}
    [first] = Regex.run(~r/TBR-[0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5}/, first_text)

    {:ok, [[verifier, salt]]} =
      DB.query(db, "SELECT verifier, salt FROM recovery_secrets WHERE userId = 'george'")

    assert verifier == Native.argon2id(first, salt)
    assert [_] = alerts(db, "recovery-enrolled")

    assert %{user_id: "george"} = DeviceLifecycle.enroll(db, call)
    assert_received {:tightbeam_ephemeral, second_text}
    [second] = Regex.run(~r/TBR-[0-9A-Z-]{23}/, second_text)

    {:ok, [[verifier2, salt2]]} =
      DB.query(db, "SELECT verifier, salt FROM recovery_secrets WHERE userId = 'george'")

    refute verifier2 == Native.argon2id(first, salt2)
    assert verifier2 == Native.argon2id(second, salt2)
    assert length(alerts(db, "recovery-enrolled")) == 2

    # Non-admin device, session, org credential: refused, nothing sent or stored.
    for call <- [
          TestDevices.device_call(ctx.guest, %{verb: "recovery-enroll", params: %{}}),
          %{
            verb: "recovery-enroll",
            principal: {:session, "s"},
            auth_class: "session",
            params: %{}
          },
          %{verb: "recovery-enroll", principal: {:user, "george"}, auth_class: "org", params: %{}}
        ] do
      assert %{code: code} = DeviceLifecycle.enroll(db, call)
      assert code in ["forbidden", "user_authentication_required"]
    end

    refute_received {:tightbeam_ephemeral, _}
    assert {:ok, [[1]]} = DB.query(db, "SELECT COUNT(*) FROM recovery_secrets")
  end

  ## P9: delivery by use

  test "P9: delivery is confirmed by first sign-in; undelivered tokens clear at the deadline",
       ctx do
    db = ctx.db

    # Reply dropped after commit: the token is never used; at the deadline it clears.
    {code, _} = TestDevices.issue_code!(db, ctx.george)
    {:paired, %{token: lost}} = TestDevices.coded_pair(db, "lost", "Lost", code, ctx.admission)

    {:ok, [[deadline, generation]]} =
      DB.query(
        db,
        "SELECT deliveryDeadline, tokenGeneration FROM devices WHERE deviceId = 'lost'"
      )

    assert DeviceLifecycle.expire_due(db, deadline - 1) == 0
    assert DeviceLifecycle.expire_due(db, deadline) == 1
    assert %{token: nil, status: "allowlisted"} = Devices.by_id(db, "lost")
    assert [%{detail: detail}] = lifecycle(db, "pairing_delivery_failed")
    assert JSON.decode!(detail)["tokenGeneration"] == generation
    assert Devices.by_token(db, lost) == nil

    # Signed in in time: delivered, and a later sweep changes nothing.
    {code2, _} = TestDevices.issue_code!(db, ctx.george)
    {:paired, %{token: token}} = TestDevices.coded_pair(db, "kept", "Kept", code2, ctx.admission)
    assert :ok = sign_in(db, token)

    assert {:ok, [[1]]} =
             DB.query(db, "SELECT tokenDelivered FROM devices WHERE deviceId = 'kept'")

    assert DeviceLifecycle.expire_due(db, System.system_time(:millisecond) + 3_600_000) == 0
    assert Devices.by_token(db, token).device_id == "kept"

    # A sign-in after the deadline (the sweep not yet run) clears instead of reviving.
    {code3, _} = TestDevices.issue_code!(db, ctx.george)
    {:paired, %{token: late}} = TestDevices.coded_pair(db, "late", "Late", code3, ctx.admission)
    {:ok, _} = DB.query(db, "UPDATE devices SET deliveryDeadline = 1 WHERE deviceId = 'late'")
    assert :expired = sign_in(db, late)
    assert Devices.by_token(db, late) == nil

    # A late cleanup cannot clear a newer token: re-pair the cleared device, then run
    # a cleanup bound to the old generation.
    {code4, _} = TestDevices.issue_code!(db, ctx.george)
    {:paired, %{token: newer}} = TestDevices.coded_pair(db, "lost", "Lost", code4, ctx.admission)

    {:ok, _} =
      DB.query(
        db,
        "UPDATE devices SET token = NULL WHERE deviceId = 'lost' AND tokenGeneration = ?1 AND tokenDelivered = 0",
        [generation]
      )

    assert Devices.by_token(db, newer).device_id == "lost"
    assert :ok = sign_in(db, newer)
  end

  test "P9: a restart keeps deadlines; the sweeper clears due tokens from the table", ctx do
    {code, _} = TestDevices.issue_code!(ctx.db, ctx.george)
    {:paired, _} = TestDevices.coded_pair(ctx.db, "dev", "Dev", code, ctx.admission)
    {:ok, _} = DB.query(ctx.db, "UPDATE devices SET deliveryDeadline = 1 WHERE deviceId = 'dev'")
    assert DeviceLifecycle.next_deadline(ctx.db) == 1

    # A freshly started sweeper reads the deadline from the table and clears it.
    name = :"deadlines_#{System.unique_integer([:positive])}"

    start_supervised!(%{
      id: name,
      start: {GenServer, :start_link, [Tightbeam.DeliveryDeadlines, [db: ctx.db], [name: name]]}
    })

    Process.sleep(200)
    assert %{token: nil} = Devices.by_id(ctx.db, "dev")
  end

  ## P8a, P8: admission and racing

  test "P8a: a burst runs at most 2 verifications and queues 4; nothing outstanding, no KDF",
       ctx do
    db = ctx.db
    for _ <- 1..5, do: TestDevices.issue_code!(db, ctx.george)
    admission = :"burst_#{System.unique_integer([:positive])}"

    start_supervised!(%{
      id: admission,
      start: {PairingAdmission, :start_link, [[name: admission, rate_per_minute: 1_000]]}
    })

    results =
      1..200
      |> Task.async_stream(
        fn n ->
          Devices.pair(
            db,
            %{device_id: "burst-#{n}", claimed_name: "B TB-AAAA-BBBB-CCC#{rem(n, 9)}"},
            admission: admission
          )
        end,
        max_concurrency: 200,
        timeout: 60_000
      )
      |> Enum.map(fn {:ok, result} -> result end)

    stats = PairingAdmission.stats(admission)
    assert stats.peak <= 2
    assert Enum.count(results, &match?({:refused, "rate_limited", _}, &1)) > 0

    assert Enum.all?(
             results,
             &match?(
               {:refused, reason, _} when reason in ["rate_limited", "pairing_code_invalid"],
               &1
             )
           )

    # Gateway-wide rate: at most 30 coded pairings a minute are admitted.
    rated = :"rated_#{System.unique_integer([:positive])}"
    start_supervised!(%{id: rated, start: {PairingAdmission, :start_link, [[name: rated]]}})

    admitted =
      for _ <- 1..40, reduce: 0 do
        acc ->
          case PairingAdmission.run(rated, fn -> :ok end) do
            {:ok, :ok} -> acc + 1
            {:error, :rate_limited} -> acc
          end
      end

    assert admitted == 30

    # None outstanding, or a malformed code: refused before any admission or KDF.
    {:ok, _} = DB.query(db, "UPDATE pairing_codes SET invalidatedAt = 1")
    idle = :"idle_#{System.unique_integer([:positive])}"
    start_supervised!(%{id: idle, start: {PairingAdmission, :start_link, [[name: idle]]}})

    for name <- ["X TB-AAAA-BBBB-CCCC", "X TB-AAAA", "X TB-OOOO-IIII-LLLL", "X"] do
      assert {:refused, _, _} =
               Devices.pair(db, %{device_id: "idle", claimed_name: name}, admission: idle)
    end

    assert PairingAdmission.stats(idle).peak == 0
  end

  test "P8: an attacker racing a real coded pairing never receives a token", ctx do
    db = ctx.db

    for n <- 1..200 do
      {code, _} = TestDevices.issue_code!(db, ctx.george)
      id = "race-#{n}"
      wrong = "TB-#{String.slice(code, 3, 4)}-ZZZZ-ZZZZ"

      tasks = [
        Task.async(fn ->
          {:real, TestDevices.coded_pair(db, id, "iPad", code, ctx.admission)}
        end),
        Task.async(fn ->
          {:attacker,
           Devices.pair(db, %{device_id: id, claimed_name: "iPad"}, admission: ctx.admission)}
        end),
        Task.async(fn ->
          {:attacker, TestDevices.coded_pair(db, id, "iPad", wrong, ctx.admission)}
        end)
      ]

      results = Task.await_many(tasks, 30_000)
      refute Enum.any?(results, &match?({:attacker, {:paired, _}}, &1))
      assert [{:real, outcome}] = Enum.filter(results, &match?({:real, _}, &1))
      assert match?({:paired, _}, outcome) or match?({:refused, "rate_limited", _}, outcome)

      {:ok, used} =
        DB.query(
          db,
          "SELECT COUNT(*) FROM pairing_codes WHERE usedAt IS NOT NULL AND usedByDeviceId = ?1",
          [id]
        )

      assert used in [[[0]], [[1]]]
    end
  end

  ## P1: upgrade from core (A)

  test "P1: after the upgrade the freeze is gone, the hatch is ignored once, devices keep working",
       ctx do
    db = ctx.db

    # Existing devices: tokens unchanged and delivered.
    assert Devices.by_token(db, ctx.george.token).device_id == "iphone"
    assert :ok = sign_in(db, ctx.george.token)

    # Without the hatch file nothing is recorded at boot.
    :ok = DeviceLifecycle.observe_at_boot(db, @absent)
    assert lifecycle(db, "pairing_unfreeze_ignored") == []

    # With it: one record and one alert, and it changes nothing about pairing.
    hatch = Path.join(System.tmp_dir!(), "pairing-unfreeze-#{System.unique_integer([:positive])}")
    File.write!(hatch, "")
    on_exit(fn -> File.rm(hatch) end)
    :ok = DeviceLifecycle.observe_at_boot(db, hatch)
    assert [_] = lifecycle(db, "pairing_unfreeze_ignored")
    assert [body] = alerts(db, "pairing-unfreeze-ignored")
    assert body =~ "no longer has any effect. Remove it with `sudo rm`."

    Application.put_env(:tightbeam, :pairing_unfreeze_path, hatch)

    assert {:refused, "pairing_code_required", _} =
             Devices.pair(db, %{device_id: "new", claimed_name: "New"}, admission: ctx.admission)

    {code, _} = TestDevices.issue_code!(db, ctx.george)
    assert {:paired, _} = TestDevices.coded_pair(db, "new", "New", code, ctx.admission)

    # An admin device revokes an existing device; its token no longer authenticates.
    revoke =
      TestDevices.device_call(ctx.george, %{
        verb: "revoke-device",
        params: %{device_id: "guest-phone"}
      })

    assert :ok = Devices.revoke_with_firehose(db, "guest-phone", revoke)
    assert Devices.by_token(db, ctx.guest.token) == nil
  end

  test "S1.3/S1.5: recoveries and root actions recorded while stopped alert once at start", ctx do
    db = ctx.db
    at = System.system_time(:millisecond)

    for {kind, code} <- [
          {"admin-recovered", "pc_0000000000000001"},
          {"root-pairing-code", "pc_0000000000000002"},
          {"root-recovery-enroll", nil}
        ] do
      {:ok, _} =
        DB.query(
          db,
          "INSERT INTO gateway_host_actions (kind, userId, codeId, account, tty, at) VALUES (?1, 'george', ?2, 'george', '/dev/pts/3', ?3)",
          [kind, code, at]
        )
    end

    :ok = DeviceLifecycle.observe_at_boot(db, @absent)
    :ok = DeviceLifecycle.observe_at_boot(db, @absent)

    assert [recovered] = alerts(db, "admin-recovered")
    assert recovered =~ "Admin devices of george were recovered at"
    assert [root_code] = alerts(db, "root-pairing-code")
    assert root_code =~ "issued a pairing code for george"
    assert root_code =~ "(by george on /dev/pts/3)"
    assert [enrol] = alerts(db, "root-recovery-enroll")
    assert enrol =~ "enrolled a recovery secret"

    {:ok, wakes} =
      DB.query(db, "SELECT sessionKey FROM wakes WHERE class = 'blocker' ORDER BY sessionKey")

    # One blocker wake per action for George's Main (the only admin).
    assert length(wakes) == 3
    assert Enum.all?(wakes, &(&1 == [Org.personal_session_key("george")]))

    assert {:ok, [[0]]} =
             DB.query(db, "SELECT COUNT(*) FROM gateway_host_actions WHERE alertedAt IS NULL")

    # The alert bodies name users, times and accounts only.
    refute Enum.any?(alerts(db, "root-pairing-code"), &(&1 =~ "TB-"))
    _ = OwnerAlerts
  end

  test "the base-directory lock is exclusive and released with its holder" do
    dir = Path.join(System.tmp_dir!(), "lock-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)
    path = Path.join(dir, "gateway.lock")

    holder =
      Task.async(fn ->
        lock = Native.base_lock(path)

        receive do
          :release -> lock
        end
      end)

    Process.sleep(100)
    assert_raise ErlangError, fn -> Native.base_lock(path) end
    send(holder.pid, :release)
    Task.await(holder)
    :erlang.garbage_collect()
    Process.sleep(50)
    assert is_reference(Native.base_lock(path))
  end

  test "S1.2: the base lock is refused while another holder has it, and free once released" do
    dir = Path.join(System.tmp_dir!(), "baselock-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)
    path = Path.join(dir, "gateway.lock")
    parent = self()

    ceremony =
      spawn(fn ->
        lock = Native.base_lock(path)
        send(parent, :held)

        receive do
          :release -> lock
        end
      end)

    assert_receive :held
    assert {:error, {:base_dir_locked, ^path}} = Tightbeam.BaseLock.acquire(dir)
    ref = Process.monitor(ceremony)
    send(ceremony, :release)
    assert_receive {:DOWN, ^ref, :process, _, _}

    assert {:ok, lock} = Tightbeam.BaseLock.acquire(dir)
    assert_raise ErlangError, fn -> Native.base_lock(path) end
    _ = lock
  end

  test "the gateway's and the CLI's verifiers are byte-identical" do
    # The same input, salt and parameters as cli/src/device_recovery.rs's test vector.
    assert Native.argon2id("TB-7K3M-Q9ZD-2WH8", :binary.copy(<<7>>, 16)) ==
             Native.argon2id(
               DeviceLifecycle.canonical(" tb-7k3m-q9zd-2wh8 "),
               :binary.copy(<<7>>, 16)
             )

    assert Base.encode16(Native.argon2id("TB-7K3M-Q9ZD-2WH8", :binary.copy(<<7>>, 16)),
             case: :lower
           ) ==
             File.read!(Path.expand("../cli/src/device_recovery_vector.txt", __DIR__))
             |> String.trim()
  end
end
