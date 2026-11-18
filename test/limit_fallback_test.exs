defmodule Tightbeam.LimitFallbackTest do
  use Tightbeam.TestCase, async: false

  alias Tightbeam.{
    Archetypes,
    Assignments,
    DB,
    Gateway,
    LimitFallback,
    Ledger,
    Model,
    Org,
    Projection,
    Rules,
    Schema,
    SessionLane
  }

  alias Tightbeam.DB.Txn

  @shape "limit-fallback-v1-016"
  @predecessor "user-removal-v1-016"
  @process_branch "(kind = 'progress' AND bySession IS NULL AND byUser IS NULL " <>
                    "AND verdictKind IS NULL AND byProcess IS NOT NULL)"
  @note "model-fallback applied session=holder from=codex/gpt-6-luna/max " <>
          "to=claude/claude-opus-5-5/high readback=claude/claude-opus-5-5/high " <>
          "since=2026-11-17T00:00:00Z trigger=7 class=rate-limit-dead " <>
          "evidence=usageLimitExceeded failed-turn=replayed"

  setup do
    db = :"limit_fallback_db_#{System.unique_integer([:positive])}"
    start_supervised!({DB, path: ":memory:", name: db})
    :ok = Schema.ensure_all(db)

    register_hosts(db, %{
      "lab1" => %{
        ssh: nil,
        base_dir: Application.fetch_env!(:tightbeam, :base_dir),
        cli_bin: nil
      }
    })

    {:ok, _} =
      DB.query(
        db,
        "INSERT INTO users (userId, isAdmin, createdAt) VALUES ('flynn', 0, 1)"
      )

    session!(db, "holder")
    handlers = Gateway.handlers(%{db: db, wake_tick_ms: 1_000})
    Rules.load!(System.tmp_dir!(), Map.keys(handlers))
    %{db: db, handlers: handlers}
  end

  describe "schema (stamp #{@shape})" do
    test "a fresh database reaches the limit-fallback stamp with every object", ctx do
      assert {:ok, [[@shape]]} = DB.query(ctx.db, "SELECT shape FROM schema_stamp")
      assert hd(Schema.guard_compatible_stamps()) == @shape

      assert {:ok, [["fallbackActive"], ["limitFallbackOff"]]} =
               DB.query(
                 ctx.db,
                 "SELECT name FROM pragma_table_info('sessions') WHERE name IN ('limitFallbackOff','fallbackActive') ORDER BY name"
               )

      assert {:ok, [["byProcess"]]} =
               DB.query(
                 ctx.db,
                 "SELECT name FROM pragma_table_info('attests') WHERE name='byProcess'"
               )

      assert {:ok,
              [["table", "limit_fallback_evaluations"], ["index", "limit_fallback_open_holds"]]} =
               DB.query(
                 ctx.db,
                 "SELECT type, name FROM sqlite_master WHERE name LIKE 'limit_fallback_%' ORDER BY name"
               )

      # A restart validates and changes nothing.
      before = objects(ctx.db)
      assert :ok = Schema.ensure_all(ctx.db)
      assert objects(ctx.db) == before
    end

    test "the attests migration keeps old rows and admits only the process progress attest",
         ctx do
      assignment = assign!(ctx)

      assert %{attest: %{id: session_attest}} = session_progress!(ctx, assignment.id, "halfway")

      rewind_to_predecessor!(ctx.db)
      assert {:ok, [[@predecessor]]} = DB.query(ctx.db, "SELECT shape FROM schema_stamp")
      old_attests = attest_rows(ctx.db)
      old_sessions = session_rows(ctx.db)
      assert Enum.any?(old_attests, &(hd(&1) == session_attest))

      # The predecessor refuses a progress attest without a session author.
      assert {:error, _} = insert_attest(ctx.db, assignment.id, "progress", @note, %{})

      assert :ok = Schema.ensure_all(ctx.db)
      assert {:ok, [[@shape]]} = DB.query(ctx.db, "SELECT shape FROM schema_stamp")

      # Every existing row survives unchanged, with no process author.
      assert attest_rows(ctx.db) == old_attests
      assert session_rows(ctx.db) == old_sessions

      assert {:ok, [[0]]} =
               DB.query(ctx.db, "SELECT COUNT(*) FROM attests WHERE byProcess IS NOT NULL")

      # The one admitted shape, through the writer phase 2 calls.
      {:ok, attest} =
        DB.transaction(ctx.db, fn txn ->
          Assignments.record_model_fallback_attest_in_txn(txn, assignment.id, @note)
        end)

      assert %{kind: "progress", bySession: nil, byUser: nil, byProcess: "process:tightbeam"} =
               attest

      assert attest.note == @note

      listed = Assignments.list_attests(ctx.db, assignment.id)
      assert Enum.find(listed, &(&1.id == attest.id)).byProcess == "process:tightbeam"
      refute Map.has_key?(Enum.find(listed, &(&1.id == session_attest)), :byProcess)

      # Everything else without a session or user author is still refused.
      for {kind, note, extra} <- [
            {"progress", @note, %{}},
            {"progress", "model-fallback withheld session=holder",
             %{byProcess: "process:tightbeam"}},
            {"progress", @note, %{byProcess: "process:other"}},
            {"progress", @note, %{byProcess: "process:tightbeam", bySession: "holder"}},
            {"progress", @note, %{byProcess: "process:tightbeam", byUser: "flynn"}},
            {"completion", @note, %{byProcess: "process:tightbeam"}},
            {"surrender", @note, %{byProcess: "process:tightbeam"}},
            {"cannot-proceed", @note, %{byProcess: "process:tightbeam"}},
            {"verdict", @note, %{byProcess: "process:tightbeam", verdictKind: "clean"}}
          ] do
        assert {:error, _} = insert_attest(ctx.db, assignment.id, kind, note, extra),
               "admitted #{kind} #{inspect(extra)}"
      end

      # Session-authored attests are unchanged.
      assert %{attest: %{bySession: "holder"}} =
               session_progress!(ctx, assignment.id, "still working")

      assert {:error, %ArgumentError{}} =
               DB.transaction(ctx.db, fn txn ->
                 Assignments.record_model_fallback_attest_in_txn(txn, assignment.id, "applied")
               end)
    end

    test "a rewound stamp re-runs over the exact objects; any other shape is refused", ctx do
      before = objects(ctx.db)
      {:ok, _} = DB.query(ctx.db, "UPDATE schema_stamp SET shape=?1", [@predecessor])
      assert :ok = Schema.ensure_all(ctx.db)
      assert {:ok, [[@shape]]} = DB.query(ctx.db, "SELECT shape FROM schema_stamp")
      assert objects(ctx.db) == before

      :ok =
        DB.execute(ctx.db, """
        DROP INDEX limit_fallback_open_holds;
        CREATE INDEX limit_fallback_open_holds ON limit_fallback_evaluations (sessionKey);
        """)

      error = assert_raise Schema.ShapeError, fn -> Schema.ensure_all(ctx.db) end
      assert error.message =~ "limit_fallback_open_holds"
    end
  end

  describe "session state" do
    test "the fallback-off marker records actor, time and reason, and clears", ctx do
      refute LimitFallback.restricted?(Org.get(ctx.db, "holder"))

      {:ok, session} =
        DB.transaction(ctx.db, fn txn ->
          LimitFallback.set_restriction_in_txn(txn, "holder", :off, "user:flynn", "claude-only")
        end)

      assert LimitFallback.restricted?(session)
      assert %{by: "user:flynn", reason: "claude-only", at: at} = session.limit_fallback_off
      assert is_integer(at)
      assert Org.get(ctx.db, "holder").limit_fallback_off == session.limit_fallback_off

      {:ok, session} =
        DB.transaction(ctx.db, fn txn ->
          LimitFallback.set_restriction_in_txn(txn, "holder", :on, "user:flynn", nil)
        end)

      refute LimitFallback.restricted?(session)
      refute LimitFallback.restricted?(Org.get(ctx.db, "holder"))
    end

    test "fallback-active carries since, the from tuple and the trigger", ctx do
      from = Model.new("gpt-6-luna", effort: "max")

      {:ok, session} =
        DB.transaction(ctx.db, fn txn ->
          LimitFallback.set_fallback_active_in_txn(txn, "holder", %{
            since: 1_700,
            from: %{harness: "codex", model: from},
            trigger: {:turn, 42}
          })
        end)

      assert LimitFallback.fallback_active?(session)

      assert Org.get(ctx.db, "holder").fallback_active == %{
               since: 1_700,
               from: %{harness: "codex", model: from},
               trigger: "turn:42"
             }

      assert Tightbeam.Wire.Payloads.stream_session(session)["fallbackActive"] == %{
               "since" => 1_700,
               "trigger" => "turn:42",
               "from" => %{
                 "harness" => "codex",
                 "model" => "gpt-6-luna",
                 "effort" => "max",
                 "context" => nil
               }
             }

      {:ok, cleared} =
        DB.transaction(ctx.db, &LimitFallback.clear_fallback_active_in_txn(&1, "holder"))

      refute LimitFallback.fallback_active?(cleared)
      refute Map.has_key?(Tightbeam.Wire.Payloads.stream_session(cleared), "fallbackActive")
    end
  end

  describe "claim hold and outcome" do
    test "one hold and one outcome per trigger; the outcome releases the hold", ctx do
      seq = enqueue!(ctx.db, "holder", "failed turn")

      {:ok, {:held, held}} =
        DB.transaction(ctx.db, &LimitFallback.hold_in_txn(&1, "holder", seq))

      assert %{trigger: {:turn, ^seq}, outcome: nil} = held
      assert LimitFallback.held?(ctx.db, "holder")

      assert {:ok, {:already_held, _}} =
               DB.transaction(ctx.db, &LimitFallback.hold_in_txn(&1, "holder", seq))

      assert {:ok, [%{trigger: {:turn, ^seq}}]} =
               DB.transaction(ctx.db, &LimitFallback.outstanding_holds_in_txn/1)

      assert {:ok, {:recorded, %{outcome: "withheld", reason: "switch-failed:interrupted"}}} =
               DB.transaction(ctx.db, fn txn ->
                 LimitFallback.record_outcome_in_txn(
                   txn,
                   "holder",
                   {:turn, seq},
                   {:withheld, "switch-failed:interrupted"}
                 )
               end)

      refute LimitFallback.held?(ctx.db, "holder")
      assert {:ok, []} = DB.transaction(ctx.db, &LimitFallback.outstanding_holds_in_txn/1)

      # Exactly once: a re-entered evaluation of the same trigger writes nothing.
      assert {:ok, {:duplicate, %{outcome: "withheld"}}} =
               DB.transaction(ctx.db, fn txn ->
                 LimitFallback.record_outcome_in_txn(txn, "holder", {:turn, seq}, :applied)
               end)

      assert {:ok, {:decided, %{outcome: "withheld"}}} =
               DB.transaction(ctx.db, &LimitFallback.hold_in_txn(&1, "holder", seq))

      refute LimitFallback.held?(ctx.db, "holder")

      # An incident trigger (no hold) records its outcome once as well.
      assert {:ok, {:recorded, %{outcome: "applied", held_at: nil}}} =
               DB.transaction(ctx.db, fn txn ->
                 LimitFallback.record_outcome_in_txn(
                   txn,
                   "holder",
                   {:incident, "inc_1"},
                   :applied
                 )
               end)

      assert {:ok, {:duplicate, _}} =
               DB.transaction(ctx.db, fn txn ->
                 LimitFallback.record_outcome_in_txn(
                   txn,
                   "holder",
                   {:incident, "inc_1"},
                   :applied
                 )
               end)
    end

    test "the lane claims nothing while a hold stands and claims once it is released", ctx do
      start_supervised!({Registry, keys: :unique, name: Tightbeam.LaneRegistry})
      task_sup = start_supervised!({Task.Supervisor, name: :limit_fallback_lane_tasks})
      seq = enqueue!(ctx.db, "holder", "queued behind the limit")

      {:ok, {:held, _}} = DB.transaction(ctx.db, &LimitFallback.hold_in_txn(&1, "holder", seq))

      parent = self()

      lane =
        start_supervised!(
          {SessionLane,
           session_key: "holder",
           db: ctx.db,
           task_sup: task_sup,
           runner: fn turn ->
             send(parent, {:claimed, turn.seq})
             {:ok, %{}}
           end}
        )

      # The lane's boot nudge and this nudge are both handled before the call.
      SessionLane.nudge("holder")
      :sys.get_state(lane)
      refute_received {:claimed, _}

      assert {:ok, [["queued"]]} =
               DB.query(ctx.db, "SELECT status FROM turns WHERE seq=?1", [seq])

      {:ok, {:recorded, _}} =
        DB.transaction(ctx.db, fn txn ->
          LimitFallback.record_outcome_in_txn(txn, "holder", {:turn, seq}, {:withheld, "main"})
        end)

      SessionLane.nudge("holder")
      assert_receive {:claimed, ^seq}, 5_000
    end
  end

  test "publishing a limit_fallback retunes no session and the next lookup uses it", ctx do
    base_dir =
      Path.join(System.tmp_dir!(), "tb-limit-fallback-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(base_dir) end)
    manifest = Path.join([base_dir, "identity", "archetypes", "coderish.toml"])
    File.mkdir_p!(Path.dirname(manifest))

    preferences = """
    name = "coderish"

    [[model_preferences]]
    model = "gpt-6-luna"
    effort = "max"

    [[model_preferences]]
    model = "claude-opus-5-5"
    effort = "high"
    """

    File.write!(manifest, preferences)
    Archetypes.load!(base_dir)
    session!(ctx.db, "coder-session", %{archetype: "coderish"})
    before = Org.get(ctx.db, "coder-session")
    assert LimitFallback.configured(before) == nil

    File.write!(
      manifest,
      preferences <> "\n[limit_fallback]\nmodel = \"claude-opus-5-5\"\neffort = \"high\"\n"
    )

    Archetypes.load!(base_dir)

    assert Org.get(ctx.db, "coder-session") == before

    assert LimitFallback.configured(before) == %{
             model: Model.new("claude-opus-5-5", effort: "high"),
             harness: nil
           }
  end

  defp session!(db, key, overrides \\ %{}) do
    Org.create(
      db,
      Map.merge(
        %{
          session_key: key,
          display_name: key,
          kind: "custom",
          owner_user_id: "flynn",
          origin: "user:flynn",
          archetype: "default",
          harness: "codex",
          provider: "openai",
          model: Model.new("gpt-6-luna", effort: "max"),
          host: "lab1"
        },
        overrides
      )
    )
  end

  defp assign!(ctx) do
    Assignments.__handle__(ctx.db, "assign", %{
      verb: "assign",
      origin: "user:flynn",
      principal: {:user, "flynn"},
      session_key: "holder",
      target_role: nil,
      role_fallback: false,
      supervision_interval_ms: 1_000,
      params: %{subject: "work", idempotency_key: nil, work_item_id: nil}
    })
  end

  defp session_progress!(ctx, assignment_id, note) do
    Assignments.__handle__(ctx.db, "attest", %{
      verb: "attest",
      origin: "agent:holder",
      principal: {:session, "holder"},
      session_key: nil,
      params: %{assignment_id: assignment_id, kind: "progress", note: note}
    })
  end

  defp enqueue!(db, session_key, prompt) do
    {:appended, message} =
      Projection.append(db, %{session_key: session_key, role: "user", content: prompt})

    {:ok, seq} =
      Ledger.enqueue(db, %{
        session_key: session_key,
        message_id: message.id,
        origin: "user:flynn",
        prompt: prompt
      })

    seq
  end

  # A raw row, naming byProcess only when the case sets it (the predecessor has
  # no such column).
  defp insert_attest(db, assignment_id, kind, note, extra) do
    values =
      Map.merge(
        %{
          id: "att_raw_#{System.unique_integer([:positive])}",
          assignmentId: assignment_id,
          kind: kind,
          note: note,
          ts: 1
        },
        extra
      )

    columns = Map.keys(values)
    names = Enum.map_join(columns, ", ", &Atom.to_string/1)
    placeholders = Enum.map_join(1..length(columns), ", ", &"?#{&1}")

    DB.query(
      db,
      "INSERT INTO attests (#{names}) VALUES (#{placeholders})",
      Enum.map(columns, &Map.fetch!(values, &1))
    )
  end

  defp attest_rows(db) do
    {:ok, rows} =
      DB.query(
        db,
        "SELECT id, assignmentId, kind, verdictKind, note, bySession, byUser, ts FROM attests ORDER BY id"
      )

    rows
  end

  defp session_rows(db) do
    {:ok, rows} =
      DB.query(
        db,
        "SELECT sessionKey, harness, provider, model, thinkingLevel, modelContext, host, state FROM sessions ORDER BY sessionKey"
      )

    rows
  end

  defp objects(db) do
    {:ok, rows} =
      DB.query(db, "SELECT type, name, sql FROM sqlite_master ORDER BY type, name")

    rows
  end

  # Undo exactly what the limit-fallback migration added, returning the database
  # to its predecessor stamp: the attests CHECK alternative, the three columns,
  # and the evaluation record.
  defp rewind_to_predecessor!(db) do
    {:ok, :ok} =
      DB.migration_transaction(
        db,
        :test_rewind_attests,
        [],
        ["PRAGMA writable_schema = OFF"],
        fn txn ->
          [[sql]] =
            Txn.q(txn, "SELECT sql FROM sqlite_master WHERE type='table' AND name='attests'")

          restored = String.replace(sql, "\n      OR\n      " <> @process_branch, "")
          true = restored != sql
          :ok = Txn.exec(txn, "DROP INDEX limit_fallback_open_holds")
          :ok = Txn.exec(txn, "DROP TABLE limit_fallback_evaluations")
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
      DB.migration_transaction(db, :test_rewind_columns, [], [], fn txn ->
        :ok = Txn.exec(txn, "ALTER TABLE attests DROP COLUMN byProcess")
        :ok = Txn.exec(txn, "ALTER TABLE sessions DROP COLUMN limitFallbackOff")
        :ok = Txn.exec(txn, "ALTER TABLE sessions DROP COLUMN fallbackActive")
        Txn.q(txn, "UPDATE schema_stamp SET shape=?1", [@predecessor])
        :ok
      end)
  end
end
