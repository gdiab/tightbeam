defmodule Tightbeam.UserRemovalCrossLineTest do
  # Cross-line migration contract v3.1 (art_669dd19a), 0.1.16 tests: the
  # user-removal adoption (v2) and item 6's limit-fallback step (R7, R8, R10).
  # F0 is a base written by the 0.1.14 + PR622 build (stamp user-removal-v1-0114,
  # with a removed user). Every case boots it through the guarded persistent
  # path: the marked base, the build transition, the guard, ensure_all, then the
  # marker publication. The cases on F1 (a base written by the reviewed Part-A
  # 0.1.14 build, stamp limit-fallback-v1-0114: T7, T9-T11, N8-N12) wait for
  # that build and are not here.
  use Tightbeam.TestCase, async: false

  alias Exqlite.Sqlite3
  alias Tightbeam.{DB, LimitFallback, LiveBaseAdmission, LiveBaseGuard, Schema, UserAdmin}
  alias Tightbeam.DB.Txn

  @u_l "user-removal-v1-016"
  @lf_l "limit-fallback-v1-016"
  @p_l "artifact-process-attribution-v1-015"
  @f0_dir Path.expand("fixtures/user_removal/f0", __DIR__)
  @removal_check "removedBy TEXT CHECK ((removedAt IS NULL) = (removedBy IS NULL))"
  @process_branch "(kind = 'progress' AND bySession IS NULL AND byUser IS NULL " <>
                    "AND verdictKind IS NULL AND byProcess IS NOT NULL)"

  setup do
    suffix = System.unique_integer([:positive])
    root = Path.join(File.cwd!(), ".tmp-user-removal-#{suffix}")
    base = Path.join(File.cwd!(), ".tmp-user-removal-base-#{suffix}")
    app = Path.join(root, "release/lib/tightbeam-0.1.16")
    File.mkdir_p!(Path.join(app, "ebin"))
    File.mkdir_p!(Path.join(app, "priv"))
    File.write!(Path.join(app, "ebin/fixture.beam"), "fixture beam")
    File.write!(Path.join(app, "priv/fixture.rule"), "fixture rule")
    File.mkdir_p!(Path.join(root, "bin"))
    File.write!(Path.join(root, "package.json"), ~s({"name":"tightbeam"}))
    File.write!(Path.join(root, "bin/tightbeam"), "fixture")
    File.write!(Path.join(root, "bin/tightbeam-gateway"), "fixture")
    File.write!(Path.join(root, "release/README"), "fixture")

    File.write!(
      Path.join(root, "release-provenance.json"),
      JSON.encode!(%{
        "commit" => String.duplicate("a", 40),
        "format" => "tightbeam-release-provenance/v1",
        "repository" => "clickety-clacks/tightbeam",
        "tag" => "v0.1.16+1"
      })
    )

    {:ok, manifest} = LiveBaseGuard.generate_manifest(LiveBaseAdmission.payload_files!(app))
    File.write!(Path.join(app, "build-manifest.json"), JSON.encode!(manifest))

    on_exit(fn ->
      File.rm_rf!(root)
      File.rm_rf!(base)
    end)

    %{app: app, base: base, identity: manifest["buildIdentity"]}
  end

  describe "F0, the real 0.1.14 + PR622 base" do
    test "the fixture is the recorded F0 and carries a removed user", ctx do
      recorded = @f0_dir |> Path.join("state.db.sha256") |> File.read!() |> String.trim()
      assert :crypto.hash(:sha256, f0_bytes()) |> Base.encode16(case: :lower) == recorded

      stage_f0!(ctx.base)
      path = db_path(ctx.base)
      assert raw(path, "SELECT shape FROM schema_stamp") == [["user-removal-v1-0114"]]

      assert [[_, _]] =
               raw(path, "SELECT userId, removedBy FROM users WHERE removedAt IS NOT NULL")

      assert length(raw(path, "SELECT userId FROM users")) >= 3
    end
  end

  describe "T: the adoption path" do
    test "T1 and T3: ported 0.1.16 boots F0 to its head limit-fallback-v1-016, keeps every row, twice",
         ctx do
      stage_f0!(ctx.base)
      path = db_path(ctx.base)
      before = snapshot(path)

      [[removed_id, _]] =
        raw(path, "SELECT userId, removedBy FROM users WHERE removedAt IS NOT NULL")

      db = guarded_boot!(ctx)

      try do
        assert {:ok, [[@lf_l]]} = DB.query(db, "SELECT shape FROM schema_stamp")
        assert marker(ctx.base) == owner_marker(ctx.identity)
        assert_preserved!(db, before)

        assert UserAdmin.removed?(db, removed_id)

        assert Enum.any?(
                 UserAdmin.list(db),
                 &(&1["userId"] == removed_id and &1["state"] == "removed")
               )
      after
        :ok = GenServer.stop(db)
      end

      after_first = snapshot(path)
      first_schema = schema_sql(path)

      # T3: a second guarded boot changes nothing.
      db = guarded_boot!(ctx)

      try do
        assert {:ok, [[@lf_l]]} = DB.query(db, "SELECT shape FROM schema_stamp")
      after
        :ok = GenServer.stop(db)
      end

      # The second boot makes no schema change, keeps every users row and
      # every row of the first boot's result, and leaves the stamp at U_L.
      assert schema_sql(path) == first_schema
      second = snapshot(path)
      assert List.keyfind(second, "users", 0) == List.keyfind(after_first, "users", 0)

      for {table, _columns, rows} <- after_first do
        {^table, _, now} = List.keyfind(second, table, 0)
        assert rows -- now == [], "second boot changed or lost rows in #{table}"
      end
    end

    test "T2 and T3: a pre-removal 0.1.16 database gains null columns and is unchanged after",
         ctx do
      stage_f0!(ctx.base)
      db = guarded_boot!(ctx)
      :ok = Tightbeam.SchemaShapeRuntimeFixture.downgrade_user_removal!(db)
      assert {:ok, [[@p_l]]} = DB.query(db, "SELECT shape FROM schema_stamp")
      {:ok, users} = DB.query(db, "SELECT userId, isAdmin, createdAt FROM users ORDER BY userId")
      :ok = GenServer.stop(db)

      for _boot <- 1..2 do
        db = guarded_boot!(ctx)

        try do
          assert {:ok, [[@lf_l]]} = DB.query(db, "SELECT shape FROM schema_stamp")

          assert {:ok, ^users} =
                   DB.query(db, "SELECT userId, isAdmin, createdAt FROM users ORDER BY userId")

          assert {:ok, [[0]]} =
                   DB.query(
                     db,
                     "SELECT COUNT(*) FROM users WHERE removedAt IS NOT NULL OR removedBy IS NOT NULL"
                   )

          assert users_sql(db) =~ @removal_check
        after
          :ok = GenServer.stop(db)
        end
      end
    end

    test "T4 and T5: adoption alone restores the predecessor; a reboot completes", ctx do
      stage_f0!(ctx.base)
      path = db_path(ctx.base)
      before = snapshot(path)

      # T4: stop at the first migration after adoption.
      {db, boundary} = guarded_boot_until!(ctx, :user_removal_adoption)

      try do
        assert {:ok, [["session-identity-v1-0114"]]} =
                 DB.query(db, "SELECT shape FROM schema_stamp")

        assert users_sql_db(db) =~ @removal_check
        assert marker(ctx.base) != owner_marker(ctx.identity)
      after
        GenServer.stop(boundary)
        :ok = GenServer.stop(db)
      end

      # T5: a crash between adoption and this line's own step, then a reboot.
      {db, boundary} = guarded_boot_without!(ctx, :user_removal)

      try do
        assert {:ok, [[@p_l]]} = DB.query(db, "SELECT shape FROM schema_stamp")
      after
        GenServer.stop(boundary)
        :ok = GenServer.stop(db)
      end

      db = guarded_boot!(ctx)

      try do
        assert {:ok, [[@lf_l]]} = DB.query(db, "SELECT shape FROM schema_stamp")
        assert marker(ctx.base) == owner_marker(ctx.identity)
        assert_preserved!(db, before)
      after
        :ok = GenServer.stop(db)
      end
    end
  end

  describe "N: refusals change nothing" do
    test "N1: F0 without removedBy refuses at adoption", ctx do
      stage_f0!(ctx.base)
      mutate!(ctx.base, "ALTER TABLE users DROP COLUMN removedBy")
      assert_refused_unchanged!(ctx, ~r/incompatible user removal column: removedBy/)
    end

    test "N2: F0 with removedAt retyped TEXT refuses at adoption", ctx do
      stage_f0!(ctx.base)

      rebuild_users!(ctx.base, """
      CREATE TABLE users_rebuilt (
        userId    TEXT PRIMARY KEY,
        isAdmin   INTEGER NOT NULL DEFAULT 0,
        createdAt INTEGER NOT NULL,
        removedAt TEXT,
        #{@removal_check}
      )
      """)

      assert_refused_unchanged!(ctx, ~r/incompatible user removal column: removedAt/)
    end

    test "N3: a sibling or unknown user-removal stamp is refused before ensure_all", ctx do
      for stamp <- ["user-removal-v1-main", "user-removal-v1-x"] do
        File.rm_rf!(ctx.base)
        stage_f0!(ctx.base)
        mutate!(ctx.base, "UPDATE schema_stamp SET shape='#{stamp}'")
        assert_refused_at_guard!(ctx)
      end
    end

    test "N4: a pre-removal database with only removedAt refuses at this line's step", ctx do
      stage_f0!(ctx.base)
      db = guarded_boot!(ctx)
      :ok = Tightbeam.SchemaShapeRuntimeFixture.downgrade_user_removal!(db)
      assert :ok = DB.execute(db, "ALTER TABLE users ADD COLUMN removedAt INTEGER")
      :ok = GenServer.stop(db)

      {:ok, db} = start_guarded!(ctx)

      try do
        assert_raise Schema.ShapeError, ~r/incompatible user removal columns/, fn ->
          Schema.ensure_all(db)
        end

        assert {:ok, [[@p_l]]} = DB.query(db, "SELECT shape FROM schema_stamp")
      after
        :ok = GenServer.stop(db)
      end
    end

    test "N6: a guard list without the adoption set refuses F0 at the guard", ctx do
      stage_f0!(ctx.base)
      before = File.read!(db_path(ctx.base))
      [[stamp]] = raw(db_path(ctx.base), "SELECT shape FROM schema_stamp")
      assert stamp == "user-removal-v1-0114"
      assert stamp in Schema.guard_compatible_stamps()

      without_adoption =
        Schema.guard_compatible_stamps() --
          ["user-removal-v1-0114", "limit-fallback-v1-0114", "user-removal-v1-015"]

      assert {:error, %{code: "incompatible_schema"}} =
               LiveBaseGuard.qualify_schema(%{expected_schema: nil}, stamp, without_adoption)

      assert File.read!(db_path(ctx.base)) == before
    end

    test "N7: F0 rebuilt without the removedBy CHECK refuses at adoption", ctx do
      stage_f0!(ctx.base)

      rebuild_users!(ctx.base, """
      CREATE TABLE users_rebuilt (
        userId    TEXT PRIMARY KEY,
        isAdmin   INTEGER NOT NULL DEFAULT 0,
        createdAt INTEGER NOT NULL,
        removedAt INTEGER,
        removedBy TEXT
      )
      """)

      assert_refused_unchanged!(ctx, ~r/incompatible user removal column: removedBy CHECK/)
    end
  end

  describe "R1b and R3" do
    test "the guard list is LF_L, U_L, P_L, the adoption set, then the existing list" do
      assert [
               @lf_l,
               @u_l,
               @p_l,
               "user-removal-v1-0114",
               "limit-fallback-v1-0114",
               "user-removal-v1-015",
               "closed-assignment-cannot-proceed-reconciliation-v1-015",
               "session-identity-v1-0114" | _
             ] = Schema.guard_compatible_stamps()

      refute "user-removal-v1-main" in Schema.guard_compatible_stamps()
    end
  end

  describe "v3.1 item 6: this line's limit-fallback step (R7, R8, R10)" do
    test "T8: this line's pre-port database reaches limit-fallback-v1-016 through user-removal-v1-016",
         ctx do
      stage_f0!(ctx.base)
      db = guarded_boot!(ctx)
      :ok = downgrade_to_pre_port!(db)
      assert {:ok, [[@p_l]]} = DB.query(db, "SELECT shape FROM schema_stamp")
      assert lf_objects(db) == []
      {:ok, users} = DB.query(db, "SELECT userId, isAdmin, createdAt FROM users ORDER BY userId")
      :ok = GenServer.stop(db)

      before = snapshot(db_path(ctx.base))

      for _boot <- 1..2 do
        db = guarded_boot!(ctx)

        try do
          assert {:ok, [[@lf_l]]} = DB.query(db, "SELECT shape FROM schema_stamp")
          assert marker(ctx.base) == owner_marker(ctx.identity)
          assert {:ok, :ok} = DB.transaction(db, &LimitFallback.validate_in_txn!/1)

          # R10: the owner-alerts objects were created over user-removal-v1-016.
          assert {:ok, [[0, "owner-alerts-v1-0114", _]]} =
                   DB.query(db, "SELECT id, shape, appliedAt FROM owner_alert_migration")

          assert {:ok, ^users} =
                   DB.query(db, "SELECT userId, isAdmin, createdAt FROM users ORDER BY userId")

          assert users_sql(db) =~ @removal_check
          assert_preserved!(db, before)
        after
          :ok = GenServer.stop(db)
        end
      end
    end

    test "a crash after this line's user-removal step resumes at the limit-fallback step", ctx do
      stage_f0!(ctx.base)
      db = guarded_boot!(ctx)
      :ok = downgrade_to_pre_port!(db)
      :ok = GenServer.stop(db)

      {db, boundary} = guarded_boot_without!(ctx, :limit_fallback)

      try do
        assert {:ok, [[@u_l]]} = DB.query(db, "SELECT shape FROM schema_stamp")
        assert {:ok, [[1]]} = DB.query(db, "SELECT COUNT(*) FROM owner_alert_migration")
        assert lf_objects(db) == []
      after
        GenServer.stop(boundary)
        :ok = GenServer.stop(db)
      end

      db = guarded_boot!(ctx)

      try do
        assert {:ok, [[@lf_l]]} = DB.query(db, "SELECT shape FROM schema_stamp")
        assert {:ok, :ok} = DB.transaction(db, &LimitFallback.validate_in_txn!/1)
      after
        :ok = GenServer.stop(db)
      end
    end

    test "R8: limit-fallback-v1-0114 without c1's objects refuses at adoption, changing nothing",
         ctx do
      # One stated mutation of F0: its stamp claims the 0.1.14 limit-fallback
      # shape while the base carries only PR622's columns.
      stage_f0!(ctx.base)
      mutate!(ctx.base, "UPDATE schema_stamp SET shape='limit-fallback-v1-0114'")

      assert_refused_unchanged!(
        ctx,
        ~r/incompatible_limit_fallback_schema/,
        "limit-fallback-v1-0114"
      )
    end

    test "R10: owner alerts are created only over user-removal-v1-016", ctx do
      stage_f0!(ctx.base)
      db = guarded_boot!(ctx)

      for name <- ["owner_alerts", "owner_alert_migration"] do
        assert :ok = DB.execute(db, "DROP TABLE #{name}")
      end

      try do
        assert_raise Schema.ShapeError, ~r/incompatible_owner_alert_predecessor/, fn ->
          Schema.ensure_all(db)
        end

        assert {:ok, [[@lf_l]]} = DB.query(db, "SELECT shape FROM schema_stamp")

        assert {:ok, []} =
                 DB.query(db, "SELECT name FROM sqlite_master WHERE name='owner_alerts'")
      after
        :ok = GenServer.stop(db)
      end
    end
  end

  # -- helpers ---------------------------------------------------------------

  # This line's pre-port shape (P_L), as a stated rewind of a booted F0: c1's
  # objects and the owner-alerts objects are removed, then PR622's columns
  # (SchemaShapeRuntimeFixture.downgrade_user_removal!/1). Every other row stays.
  defp downgrade_to_pre_port!(db) do
    {:ok, :ok} =
      DB.migration_transaction(
        db,
        :test_rewind_limit_fallback,
        [],
        ["PRAGMA writable_schema = OFF"],
        fn txn ->
          [[sql]] =
            Txn.q(txn, "SELECT sql FROM sqlite_master WHERE type='table' AND name='attests'")

          restored = String.replace(sql, "\n      OR\n      " <> @process_branch, "")
          true = restored != sql
          :ok = Txn.exec(txn, "DROP INDEX limit_fallback_open_holds")
          :ok = Txn.exec(txn, "DROP TABLE limit_fallback_evaluations")
          :ok = Txn.exec(txn, "DROP TABLE owner_alerts")
          :ok = Txn.exec(txn, "DROP TABLE owner_alert_migration")
          [[version]] = Txn.q(txn, "PRAGMA schema_version")
          :ok = Txn.exec(txn, "PRAGMA writable_schema = ON")

          Txn.q(txn, "UPDATE sqlite_master SET sql=?1 WHERE type='table' AND name='attests'", [
            restored
          ])

          :ok = Txn.exec(txn, "PRAGMA schema_version = #{version + 1}")
          :ok = Txn.exec(txn, "PRAGMA writable_schema = RESET")
          :ok
        end
      )

    {:ok, :ok} =
      DB.migration_transaction(db, :test_rewind_limit_fallback_columns, [], [], fn txn ->
        :ok = Txn.exec(txn, "ALTER TABLE attests DROP COLUMN byProcess")
        :ok = Txn.exec(txn, "ALTER TABLE sessions DROP COLUMN limitFallbackOff")
        :ok = Txn.exec(txn, "ALTER TABLE sessions DROP COLUMN fallbackActive")
        :ok
      end)

    Tightbeam.SchemaShapeRuntimeFixture.downgrade_user_removal!(db)
  end

  defp lf_objects(db) do
    {:ok, rows} =
      DB.query(
        db,
        """
        SELECT name FROM sqlite_master
        WHERE name IN ('limit_fallback_evaluations', 'limit_fallback_open_holds')
        ORDER BY name
        """
      )

    rows
  end

  # F0 is stored as gzip + base64 text, like the other SQLite fixtures; the
  # decoded bytes are the generator's file exactly (state.db.sha256).
  defp f0_bytes do
    @f0_dir
    |> Path.join("state.db.gz.b64")
    |> File.read!()
    |> String.replace(~r/\s/, "")
    |> Base.decode64!()
    |> :zlib.gunzip()
  end

  defp stage_f0!(base) do
    File.mkdir_p!(base)
    File.write!(db_path(base), f0_bytes())
    File.cp!(Path.join(@f0_dir, "build-owner.json"), Path.join(base, "build-owner.json"))
  end

  defp db_path(base), do: Path.join(base, "state.db")

  defp marker(base), do: base |> Path.join("build-owner.json") |> File.read!() |> JSON.decode!()

  defp owner_marker(identity),
    do: %{"format" => "tightbeam-build-owner/v1", "buildIdentity" => identity}

  defp start_guarded!(ctx) do
    _admission = LiveBaseAdmission.prepare!(ctx.base, payload_root: ctx.app)

    DB.start_link(
      path: db_path(ctx.base),
      name: nil,
      guard_inputs: [],
      payload_root: ctx.app
    )
  end

  defp guarded_boot!(ctx) do
    {:ok, db} = start_guarded!(ctx)
    :ok = Schema.ensure_all(db)
    db
  end

  # Boots through the guard, but refuses every migration transaction after the
  # named one, so ensure_all stops exactly there (T4).
  defp guarded_boot_until!(ctx, last) do
    {:ok, db} = start_guarded!(ctx)
    {:ok, boundary} = __MODULE__.Boundary.start_link({db, {:after, last}})

    assert_stopped!(boundary)
    {db, boundary}
  end

  # Boots through the guard, but refuses only the named migration (T5).
  defp guarded_boot_without!(ctx, name) do
    {:ok, db} = start_guarded!(ctx)
    {:ok, boundary} = __MODULE__.Boundary.start_link({db, {:only, name}})

    assert_stopped!(boundary)
    {db, boundary}
  end

  # The refused migration's caller decides how the stop surfaces (a ShapeError
  # or a failed match); either way ensure_all must not complete.
  defp assert_stopped!(boundary) do
    outcome =
      try do
        Schema.ensure_all(boundary)
      rescue
        error -> {:stopped, error}
      end

    assert {:stopped, _} = outcome
  end

  defp assert_refused_unchanged!(ctx, message, stamp \\ "user-removal-v1-0114") do
    before_db = File.read!(db_path(ctx.base))
    before_marker = File.read!(Path.join(ctx.base, "build-owner.json"))

    {:ok, db} = start_guarded!(ctx)

    try do
      assert_raise Schema.ShapeError, message, fn -> Schema.ensure_all(db) end
    after
      :ok = GenServer.stop(db)
    end

    assert raw(db_path(ctx.base), "SELECT shape FROM schema_stamp") == [[stamp]]
    assert File.read!(Path.join(ctx.base, "build-owner.json")) == before_marker
    assert snapshot_bytes(before_db) == snapshot(db_path(ctx.base))
  end

  # The automatic release transition admits only listed stamps; with an explicit
  # operator transition the guard itself refuses with incompatible_schema. Both
  # refuse before ensure_all and leave the base as it was.
  defp assert_refused_at_guard!(ctx) do
    before_db = File.read!(db_path(ctx.base))
    before_marker = File.read!(Path.join(ctx.base, "build-owner.json"))
    %{"buildIdentity" => source} = marker(ctx.base)

    assert_raise LiveBaseAdmission.Refusal, ~r/build_transition_required/, fn ->
      LiveBaseAdmission.prepare!(ctx.base, payload_root: ctx.app)
    end

    transition =
      JSON.encode!(%{
        "base" => LiveBaseAdmission.canonical!(ctx.base),
        "source" => source,
        "target" => ctx.identity
      })

    assert_raise Schema.ShapeError, ~r/incompatible_schema/, fn ->
      LiveBaseAdmission.prepare!(ctx.base, payload_root: ctx.app, transition: transition)
    end

    assert File.read!(db_path(ctx.base)) == before_db
    assert File.read!(Path.join(ctx.base, "build-owner.json")) == before_marker
  end

  defp mutate!(base, sql) do
    {:ok, conn} = Sqlite3.open(db_path(base))

    try do
      :ok = Sqlite3.execute(conn, sql)
    after
      :ok = Sqlite3.close(conn)
    end
  end

  # One stated mutation of F0's users table: rebuild it from the given DDL and
  # copy every row, keeping the stamp and every other table.
  defp rebuild_users!(base, ddl) do
    mutate!(base, """
    PRAGMA foreign_keys=OFF;
    BEGIN;
    #{ddl};
    INSERT INTO users_rebuilt (userId, isAdmin, createdAt, removedAt, removedBy)
      SELECT userId, isAdmin, createdAt, removedAt, removedBy FROM users;
    DROP TABLE users;
    ALTER TABLE users_rebuilt RENAME TO users;
    COMMIT;
    PRAGMA foreign_keys=ON;
    """)
  end

  defp users_sql(db), do: users_sql_db(db)

  defp users_sql_db(db) do
    {:ok, [[sql]]} =
      DB.query(db, "SELECT sql FROM sqlite_master WHERE type='table' AND name='users'")

    sql
  end

  # R4: every users row is byte-for-byte the same, and no row F0 had in any
  # other table is changed or lost (on F0's columns). The 0.1.16 chain may add
  # columns, and its own features may add rows (the record-event feed's
  # activation keys in org_settings), but never touch F0's.
  defp assert_preserved!(db, before) do
    for {table, columns, rows} <- before do
      select = Enum.map_join(columns, ", ", &~s["#{&1}"])

      {:ok, after_rows} =
        DB.query(db, ~s[SELECT #{select} FROM "#{table}" ORDER BY #{order(columns)}])

      if table == "users" do
        assert after_rows == rows, "rows changed in users"
      else
        missing = rows -- after_rows
        assert missing == [], "rows changed or lost in #{table}: #{inspect(missing)}"
      end
    end
  end

  defp schema_sql(path),
    do: raw(path, "SELECT type, name, sql FROM sqlite_master ORDER BY type, name")

  # Some tables are WITHOUT ROWID, so rows are ordered by every selected column.
  defp order(columns), do: Enum.map_join(1..length(columns), ", ", &Integer.to_string/1)

  defp snapshot(path) do
    tables =
      raw(
        path,
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name <> 'schema_stamp' ORDER BY name"
      )

    for [table] <- tables do
      columns = path |> raw(~s[PRAGMA table_info("#{table}")]) |> Enum.map(&Enum.at(&1, 1))
      select = Enum.map_join(columns, ", ", &~s["#{&1}"])
      {table, columns, raw(path, ~s[SELECT #{select} FROM "#{table}" ORDER BY #{order(columns)}])}
    end
  end

  defp snapshot_bytes(bytes) do
    path =
      Path.join(System.tmp_dir!(), "user-removal-before-#{System.unique_integer([:positive])}.db")

    File.write!(path, bytes)

    try do
      snapshot(path)
    after
      File.rm(path)
    end
  end

  defp raw(path, sql) do
    {:ok, conn} = Sqlite3.open(path, mode: :readonly)

    try do
      {:ok, statement} = Sqlite3.prepare(conn, sql)
      {:ok, rows} = Sqlite3.fetch_all(conn, statement)
      :ok = Sqlite3.release(conn, statement)
      rows
    after
      :ok = Sqlite3.close(conn)
    end
  end

  defmodule Boundary do
    @moduledoc false
    # Forwards every call to the DB owner, refusing chosen migration transactions
    # so ensure_all stops at a known point.
    use GenServer

    def start_link({db, rule}), do: GenServer.start_link(__MODULE__, {db, rule, :before})

    @impl true
    def init({db, rule, phase}) do
      case :persistent_term.get({DB, GenServer.whereis(db)}, []) do
        [] -> :ok
        readers -> :persistent_term.put({DB, self()}, readers)
      end

      {:ok, {db, rule, phase}}
    end

    @impl true
    def terminate(_reason, _state) do
      :persistent_term.erase({DB, self()})
      :ok
    end

    @impl true
    def handle_call({:migration_transaction, name, _, _, _} = message, _from, {db, rule, phase}) do
      case {rule, phase, name} do
        {{:only, ^name}, _, _} ->
          {:reply, {:error, "fixture boundary at #{name}"}, {db, rule, phase}}

        {{:after, ^name}, :before, _} ->
          {:reply, GenServer.call(db, message, :infinity), {db, rule, :after}}

        {{:after, _}, :after, _} ->
          {:reply, {:error, "fixture boundary after adoption"}, {db, rule, phase}}

        _ ->
          {:reply, GenServer.call(db, message, :infinity), {db, rule, phase}}
      end
    end

    def handle_call(message, _from, {db, _rule, _phase} = state),
      do: {:reply, GenServer.call(db, message, :infinity), state}
  end
end
