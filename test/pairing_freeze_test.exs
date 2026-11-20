defmodule Tightbeam.PairingFreezeTest do
  @moduledoc """
  Core fix (A) C6a: the owner's escape hatch (K7b, K7c, K7d).

  The gateway runs as the non-root test user. A valid unfreeze file is a regular
  file owned by uid 0 and gid 0, not writable by group or others, whose directory
  and that directory's parent are root-owned and not group- or other-writable.
  Without root, the tests use an existing root-owned system file as the valid
  case; on hosted CI, where passwordless sudo exists, a further test builds the
  file, its directory and its parent with sudo and walks every K7b case.
  """

  use Tightbeam.TestCase, async: false

  alias Tightbeam.{
    DB,
    Devices,
    EventLog,
    Model,
    Org,
    OwnerAlerts,
    PairingFreeze,
    Schema,
    TestDevices
  }

  @minute 60_000
  @absent "/nonexistent/tightbeam-test/pairing-unfreeze"

  setup do
    db = :"pairing_freeze_#{System.unique_integer([:positive])}"
    start_supervised!({DB, path: ":memory:", name: db})
    :ok = Schema.ensure_all(db)
    on_exit(fn -> Application.put_env(:tightbeam, :pairing_unfreeze_path, @absent) end)

    george = TestDevices.paired!(db, "george", admin: true, device_id: "iphone")
    _ada = TestDevices.paired!(db, "ada", admin: true, device_id: "ada-phone")
    _guest = TestDevices.paired!(db, "guest", device_id: "guest-phone")

    for user <- ["george", "ada", "guest"] do
      Org.create(db, %{
        session_key: Org.personal_session_key(user),
        display_name: "Main",
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
    %{db: db, george: george}
  end

  defp root_file do
    TestDevices.valid_unfreeze_file!()
  end

  defp use_path(path), do: Application.put_env(:tightbeam, :pairing_unfreeze_path, path)

  defp pair(db, device_id) do
    Devices.pair(db, %{device_id: device_id, claimed_name: "Visitor", platform: nil, model: nil})
  end

  defp approve(db, device_id, admin) do
    Devices.approve_with_firehose(
      db,
      device_id,
      nil,
      TestDevices.device_call(admin, %{verb: "approve-device", params: %{device_id: device_id}})
    )
  end

  defp lifecycle(db, kind), do: Enum.filter(EventLog.lifecycle_events(db), &(&1.kind == kind))

  defp alerts(db) do
    {:ok, rows} =
      DB.query(
        db,
        "SELECT kind, state, originSessionKey, dedupeKey, body, attempts, nextAttemptAt, createdAt FROM owner_alerts WHERE kind = 'pairing-freeze-lifted' ORDER BY createdAt"
      )

    Enum.map(rows, fn [kind, state, origin, key, body, attempts, next, created] ->
      %{
        kind: kind,
        state: state,
        origin: origin,
        dedupe_key: key,
        body: body,
        attempts: attempts,
        next_attempt_at: next,
        created_at: created
      }
    end)
  end

  defp blocker_wakes(db) do
    {:ok, rows} =
      DB.query(
        db,
        "SELECT sessionKey, prompt FROM wakes WHERE class = 'blocker' ORDER BY sessionKey"
      )

    rows
  end

  defp assert_frozen_decisions(db, admin, check) do
    before = length(lifecycle(db, "pairing_unfreeze_invalid"))
    assert {:refused, "pairing_frozen"} = pair(db, "visitor-#{System.unique_integer()}")
    {:pending, _} = TestDevices.pair(db, %{device_id: "queued", claimed_name: "Queued"})
    assert %{code: "pairing_frozen"} = approve(db, "queued", admin)

    invalid = lifecycle(db, "pairing_unfreeze_invalid")

    if check do
      assert length(invalid) == before + 2
      assert Enum.all?(Enum.drop(invalid, before), &(JSON.decode!(&1.detail)["check"] =~ check))
    else
      assert length(invalid) == before
    end
  end

  # K7b (1), (2), (3), (4), (6) without root: no file, a valid root-owned file, the
  # file removed, a file owned by the gateway user, and a symbolic link to a valid
  # root-owned file. Each is followed by a pair_request and an admin approval.
  test "K7b: only a valid root-owned file lifts the freeze, for new devices only", ctx do
    db = ctx.db
    refute System.get_env("USER") == "root"
    assert {uid_text, 0} = System.cmd("id", ["-u"])
    refute String.trim(uid_text) == "0", "the gateway under test must not run as root"

    # (1) No file: frozen.
    use_path(@absent)
    assert %{lifted: false, invalid: nil} = PairingFreeze.read()
    assert_frozen_decisions(db, ctx.george, nil)

    # (2) A valid root-owned file: new-device pairing, recorded and alerted once.
    valid = root_file()
    use_path(valid)
    assert {:pending, _} = pair(db, "new-ipad")
    approved = approve(db, "new-ipad", ctx.george)
    assert {:paired, %{token: token}} = pair(db, "new-ipad")
    assert token == approved.token

    uses = lifecycle(db, "pairing_freeze_lifted_use")

    assert Enum.map(uses, &JSON.decode!(&1.detail)["verb"]) ==
             ["pair_request", "approve-device", "pair_request"]

    assert Enum.map(uses, &JSON.decode!(&1.detail)["outcome"]) ==
             ["pending", "approved", "paired"]

    assert Enum.all?(uses, &is_integer(JSON.decode!(&1.detail)["fileMtime"]))

    assert [%{state: "pending", origin: origin, body: body}] = alerts(db)
    assert origin == Org.personal_session_key("george")
    assert body =~ "The pairing freeze is lifted on the gateway host"
    assert body =~ "If you did not lift it, an agent did"
    refute body =~ "/etc"

    # One blocker wake for every non-removed admin's Main, none for the guest.
    assert [[ada_main, ada_prompt], [george_main, _]] = blocker_wakes(db)
    assert ada_main == Org.personal_session_key("ada")
    assert george_main == Org.personal_session_key("george")
    assert ada_prompt == body

    # The alert is delivered through the injected Harklight runner.
    parent = self()

    runner = fn args ->
      send(parent, {:harklight, args})

      case args do
        ["send", "--prepare", "--op-id", op | rest] -> prepared(op, rest)
        ["send", "--execute", "--op-id", op] -> committed(op)
      end
    end

    [alert] = alerts(db)
    assert OwnerAlerts.deliver_due(db, now: alert.created_at, runner: runner) == 0
    assert_received {:harklight, ["send", "--prepare", "--op-id", _ | prepare]}
    assert ["--title", "The pairing freeze is lifted"] in Enum.chunk_every(prepare, 2, 1)
    assert [%{state: "sent"}] = alerts(db)

    # (3) The file removed: frozen at the next request, and the restoration recorded.
    use_path(@absent)
    assert_frozen_decisions(db, ctx.george, nil)
    assert [_] = lifecycle(db, "pairing_freeze_restored")

    # (4) A file owned by the gateway user is invalid.
    dir = Path.join(System.tmp_dir!(), "k7b-#{System.unique_integer([:positive])}")
    File.mkdir_p!(Path.join(dir, "tightbeam"))
    on_exit(fn -> File.rm_rf!(dir) end)
    owned = Path.join([dir, "tightbeam", "pairing-unfreeze"])
    File.write!(owned, "")
    File.chmod!(owned, 0o644)
    use_path(owned)
    assert %{lifted: false, invalid: "file_owner_uid:" <> _} = PairingFreeze.read()
    assert_frozen_decisions(db, ctx.george, "file_owner_uid")

    # (6) A symbolic link to a valid root-owned file is invalid: no link is followed.
    link = Path.join([dir, "tightbeam", "linked"])
    File.ln_s!(valid, link)
    use_path(link)
    assert %{lifted: false, invalid: "file_not_regular:symlink"} = PairingFreeze.read()
    assert_frozen_decisions(db, ctx.george, "file_not_regular:symlink")

    # Re-pair of a token holder stays refused while lifted, and no further alert
    # was raised by the requests above.
    use_path(valid)
    assert {:refused, "already_paired"} = pair(db, "iphone")
    assert length(alerts(db)) == 2
  end

  # K7c: one alert per frozen-to-lifted transition and at a boot that finds it
  # lifted, never per request; every lifted decision recorded; a failing Harklight
  # runner follows the owner-alert retry and visible-failure path.
  test "K7c: alerts once per transition and at boot; failures retry visibly", ctx do
    db = ctx.db
    valid = root_file()
    use_path(valid)

    :ok = PairingFreeze.observe_at_boot(db)
    assert [_] = alerts(db)
    assert length(blocker_wakes(db)) == 2

    for n <- 1..3, do: assert({:pending, _} = pair(db, "visitor-#{n}"))
    assert [_] = alerts(db)
    assert length(blocker_wakes(db)) == 2
    assert length(lifecycle(db, "pairing_freeze_lifted_use")) == 3

    use_path(@absent)
    assert {:refused, "pairing_frozen"} = pair(db, "visitor-4")
    use_path(valid)
    assert {:pending, _} = pair(db, "visitor-5")
    assert [first, second] = alerts(db)
    refute first.dedupe_key == second.dedupe_key
    assert length(blocker_wakes(db)) == 4
    assert [_] = lifecycle(db, "pairing_freeze_restored")

    # A3-A6: a definite Harklight failure is retried on the owner-alert schedule,
    # marked visibly in the owner's Main, and ends undelivered after 24 hours.
    failing = fn _args -> {"harklight-agent: network unreachable", 1} end
    created = first.created_at
    assert OwnerAlerts.deliver_due(db, now: created + 1, runner: failing) == 0

    [failed | _] = alerts(db)
    assert failed.state == "pending"
    assert failed.attempts >= 1
    assert failed.next_attempt_at >= created + 5 * @minute

    assert OwnerAlerts.deliver_due(db, now: created + 24 * 60 * @minute, runner: failing) == 0

    assert %{state: "undelivered", next_attempt_at: nil} =
             Enum.find(alerts(db), &(&1.dedupe_key == first.dedupe_key))

    {:ok, markers} =
      DB.query(
        db,
        "SELECT content FROM messages WHERE sessionKey = ?1 AND messageType = 'substrate'",
        [Org.personal_session_key("george")]
      )

    texts = Enum.map(markers, &hd/1)
    assert Enum.any?(texts, &(&1 =~ "Harklight delivery of an owner alert failed"))
    assert Enum.any?(texts, &(&1 =~ "undelivered"))
  end

  # K7d (code half): nothing in the gateway or the CLI writes the unfreeze path.
  test "K7d: no gateway or CLI code creates, changes or removes the unfreeze file" do
    root = Path.expand("..", __DIR__)

    sources =
      Path.wildcard(Path.join(root, "lib/**/*.ex")) ++
        Path.wildcard(Path.join(root, "cli/src/**/*.rs"))

    # The file's name, not the owner-alert kind 'pairing-unfreeze-ignored' that
    # contract v3.14 R12 folds into the owner_alerts DDL.
    naming = Enum.filter(sources, &(File.read!(&1) =~ ~r/pairing-unfreeze(?![\w-])/))
    assert Enum.map(naming, &Path.relative_to(&1, root)) == ["lib/tightbeam/pairing_freeze.ex"]

    reader = File.read!(Path.join(root, "lib/tightbeam/pairing_freeze.ex"))

    for writer <-
          ~w(File.write File.rm File.touch File.mkdir File.cp File.rename File.ln File.chmod File.chown File.open) do
      refute reader =~ writer, "pairing_freeze.ex calls #{writer}"
    end
  end

  # K7b with real root-owned files, built and changed with sudo on a disposable
  # CI runner. It never runs outside CI, where no sudo is attempted at all.
  @root_capable System.get_env("CI") == "true" and
                  match?({_, 0}, System.cmd("sudo", ["-n", "true"], stderr_to_stdout: true))
  @tag if(@root_capable, do: [], else: [skip: "needs passwordless sudo on a CI runner"])
  test "K7b: root-built files: valid, mode 0666, gateway-owned, symlink, writable directory, removed",
       ctx do
    db = ctx.db
    uid = System.cmd("id", ["-u"]) |> elem(0) |> String.trim()
    base = Path.join(System.tmp_dir!(), "k7b-root-#{System.unique_integer([:positive])}")
    etc = Path.join(base, "etc")
    dir = Path.join(etc, "tightbeam")
    file = Path.join(dir, "pairing-unfreeze")
    File.mkdir_p!(base)
    on_exit(fn -> sudo(["rm", "-rf", etc]) end)

    sudo(["install", "-d", "-o", "root", "-g", "0", "-m", "0755", etc, dir])
    sudo(["install", "-o", "root", "-g", "0", "-m", "0644", "/dev/null", file])
    use_path(file)

    # (2) Valid.
    assert %{lifted: true} = PairingFreeze.read()
    assert {:pending, _} = pair(db, "root-visitor")

    # (5) Mode 0666.
    sudo(["chmod", "0666", file])
    assert %{invalid: "file_writable_by_group_or_others"} = PairingFreeze.read()
    assert_frozen_decisions(db, ctx.george, "file_writable_by_group_or_others")
    sudo(["chmod", "0644", file])

    # (4) Owned by the gateway user.
    sudo(["chown", uid, file])
    assert %{invalid: "file_owner_uid:" <> ^uid} = PairingFreeze.read()
    assert_frozen_decisions(db, ctx.george, "file_owner_uid")
    sudo(["chown", "0:0", file])

    # (7) The directory writable by the gateway user.
    sudo(["chown", uid, dir])
    assert %{invalid: "directory_owner_uid:" <> ^uid} = PairingFreeze.read()
    assert_frozen_decisions(db, ctx.george, "directory_owner_uid")
    sudo(["chown", "0:0", dir])
    sudo(["chmod", "0777", dir])
    assert %{invalid: "directory_writable_by_group_or_others"} = PairingFreeze.read()
    sudo(["chmod", "0755", dir])

    # (6) A root-owned symbolic link to a valid root-owned file.
    real = Path.join(dir, "real")
    sudo(["install", "-o", "root", "-g", "0", "-m", "0644", "/dev/null", real])
    sudo(["rm", "-f", file])
    sudo(["ln", "-s", real, file])
    assert %{invalid: "file_not_regular:symlink"} = PairingFreeze.read()
    assert_frozen_decisions(db, ctx.george, "file_not_regular:symlink")
    sudo(["rm", "-f", file])
    sudo(["install", "-o", "root", "-g", "0", "-m", "0644", "/dev/null", file])
    assert %{lifted: true} = PairingFreeze.read()

    # (3) Removed: frozen at the next request.
    sudo(["rm", "-f", file])
    assert %{lifted: false, invalid: nil} = PairingFreeze.read()
    assert_frozen_decisions(db, ctx.george, nil)
    assert lifecycle(db, "pairing_freeze_restored") != []
  end

  defp sudo(args) do
    assert {_, 0} = System.cmd("sudo", ["-n" | args], stderr_to_stdout: true)
  end

  defp prepared(op, args) do
    frame(%{
      kind: "prepared",
      op_id: op,
      files: [],
      request: %{
        type: "send",
        op_id: op,
        session_handle: op,
        route: "other",
        message: %{
          sender_id: flag(args, "--sender-id"),
          message_id: "msg-" <> op,
          title: flag(args, "--title"),
          body: flag(args, "--body"),
          supersedes: []
        }
      }
    })
  end

  defp committed(op) do
    frame(%{
      kind: "committed",
      operation: "send",
      op_id: op,
      response: %{session_handle: op, sender_id: "tightbeam-alerts", message_id: "msg-" <> op}
    })
  end

  defp frame(value), do: {JSON.encode!(value) <> "\n", 0}
  defp flag(args, name), do: args |> Enum.drop_while(&(&1 != name)) |> Enum.at(1)
end
