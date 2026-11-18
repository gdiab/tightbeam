defmodule Tightbeam.F0UserRemovalFixtureGeneratorTest do
  # Generates F0 for the cross-line user-removal migration contract v2
  # (art_a823f882): a marked base written by this 0.1.14 + PR622 build, in
  # process. It boots this build's real schema through the guarded persistent
  # path, drives the same handlers the admin CLI dispatches to (add-user x3,
  # remove-user x1) plus a session, a work item and an assignment, publishes the
  # marker, and prints the base for the 0.1.16 test to consume byte for byte.
  # It is not driven through the CLI binary.
  use Tightbeam.TestCase, async: false

  alias Exqlite.Sqlite3
  alias Tightbeam.{DB, Devices, Gateway, LiveBaseAdmission, LiveBaseGuard, Model, Org, Schema}

  @tag timeout: 120_000
  test "writes and prints F0, a marked user-removal-v1-0114 base with a removed user" do
    suffix = System.unique_integer([:positive])
    root = Path.join(File.cwd!(), ".tmp-f0-generator-#{suffix}")
    base = Path.join(File.cwd!(), ".tmp-f0-generator-base-#{suffix}")
    app = Path.join(root, "release/lib/tightbeam-0.1.14")
    File.mkdir_p!(Path.join(app, "ebin"))
    File.mkdir_p!(Path.join(app, "priv"))
    File.write!(Path.join(app, "ebin/fixture.beam"), "fixture beam 0.1.14+pr622 3e00e479")
    File.write!(Path.join(app, "priv/fixture.rule"), "fixture rule 0.1.14+pr622")
    File.mkdir_p!(Path.join(root, "bin"))
    File.write!(Path.join(root, "package.json"), ~s({"name":"tightbeam"}))
    File.write!(Path.join(root, "bin/tightbeam"), "fixture")
    File.write!(Path.join(root, "bin/tightbeam-gateway"), "fixture")
    File.write!(Path.join(root, "release/README"), "fixture")

    File.write!(
      Path.join(root, "release-provenance.json"),
      JSON.encode!(%{
        "commit" => "3e00e479d40deee80a054e6ca9293eee75cdd857",
        "format" => "tightbeam-release-provenance/v1",
        "repository" => "clickety-clacks/tightbeam",
        "tag" => "v0.1.14+3683"
      })
    )

    {:ok, manifest} = LiveBaseGuard.generate_manifest(LiveBaseAdmission.payload_files!(app))
    File.write!(Path.join(app, "build-manifest.json"), JSON.encode!(manifest))

    on_exit(fn ->
      File.rm_rf!(root)
      File.rm_rf!(base)
    end)

    File.mkdir_p!(base)

    {:ok, db} =
      DB.start_link(
        path: Path.join(base, "state.db"),
        name: nil,
        guard_inputs: [],
        payload_root: app
      )

    :ok = Schema.ensure_all(db)
    assert {:ok, [["user-removal-v1-0114"]]} = DB.query(db, "SELECT shape FROM schema_stamp")

    handlers = Gateway.handlers(%{db: db, base_dir: base})

    # The first paired device is the cold-start admin.
    {:paired, _admin_device} =
      Devices.pair(db, %{
        device_id: "f0-admin-dev",
        claimed_name: "admin",
        platform: nil,
        model: nil
      })

    for user_id <- ["member", "member-two", "departed"] do
      assert {:ok, _} =
               run(db, handlers, "add-user", "admin", %{user_id: user_id, is_admin: false})
    end

    session =
      Org.create(db, %{
        session_key: "f0-member-session",
        display_name: "F0 member session",
        owner_user_id: "member",
        origin: "user:member",
        archetype: "default",
        host: "testhost",
        harness: "claude",
        provider: "anthropic",
        model: Model.new("fable")
      })

    item =
      handlers["work-item-create"].(%{
        verb: "work-item-create",
        origin: "user:admin",
        principal: {:user, "admin"},
        params: %{title: "F0 work item"}
      })

    assignment =
      handlers["assign"].(%{
        verb: "assign",
        origin: "user:admin",
        principal: {:user, "admin"},
        session_key: session.session_key,
        target_role: nil,
        role_fallback: false,
        params: %{subject: "F0 assignment", work_item_id: item.id}
      })

    assert is_binary(assignment.id)

    assert {:ok, %{user: %{"state" => "removed"}}} =
             run(db, handlers, "remove-user", "admin", %{user_id: "departed"})

    assert {:ok, [["departed", "user:admin"]]} =
             DB.query(db, "SELECT userId, removedBy FROM users WHERE removedAt IS NOT NULL")

    {:ok, _} = DB.query(db, "PRAGMA wal_checkpoint(TRUNCATE)")
    :ok = GenServer.stop(db)

    path = Path.join(base, "state.db")
    assert_sqlite_closed!(path)
    bytes = File.read!(path)
    marker = File.read!(Path.join(base, "build-owner.json"))
    digest = :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)
    encoded = bytes |> :zlib.gzip() |> Base.encode64()

    IO.puts("F0-BEGIN")
    IO.puts("F0-DB-SHA256 #{digest}")
    IO.puts("F0-DB-BYTES #{byte_size(bytes)}")
    IO.puts("F0-MARKER #{Base.encode64(marker)}")

    encoded
    |> chunk(4000)
    |> Enum.with_index()
    |> Enum.each(fn {line, index} -> IO.puts("F0-DB-GZ-B64 #{index} #{line}") end)

    IO.puts("F0-END")
  end

  defp run(db, handlers, verb, actor, params) do
    Tightbeam.Dispatch.dispatch(db, handlers, %{
      verb: verb,
      origin: "user:#{actor}",
      session_key: nil,
      principal: {:user, actor},
      params: params
    })
  end

  defp assert_sqlite_closed!(path) do
    {:ok, conn} = Sqlite3.open(path, mode: :readonly)
    :ok = Sqlite3.close(conn)
    wal = path <> "-wal"
    refute File.exists?(wal) and File.stat!(wal).size > 0
  end

  defp chunk(text, size) when byte_size(text) <= size, do: [text]

  defp chunk(text, size) do
    <<head::binary-size(size), rest::binary>> = text
    [head | chunk(rest, size)]
  end
end
