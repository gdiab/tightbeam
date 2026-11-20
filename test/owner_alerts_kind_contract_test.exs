defmodule Tightbeam.OwnerAlertsKindContractTest do
  @moduledoc """
  Cross-line migration contract v3.14 R12: `owner-alerts-v1-0114` has one DDL,
  whose kind CHECK names exactly eleven kinds in a fixed order. T14 checks the
  table a fresh base gets; N13 checks that every other kind list is refused
  and left untouched (no migration exists, by design).
  """

  use Tightbeam.TestCase, async: false

  alias Tightbeam.{DB, OwnerAlerts}

  @kinds ~w(usage-limit stall model-fallback memory-pressure pairing-freeze-lifted
            pairing-unfreeze-ignored recovery-enrolled admin-recovered
            root-recovery-enroll root-pairing-code memory-guard-stuck)

  @check "CHECK (kind IN ('usage-limit','stall','model-fallback','memory-pressure','pairing-freeze-lifted','pairing-unfreeze-ignored','recovery-enrolled','admin-recovered','root-recovery-enroll','root-pairing-code','memory-guard-stuck'))"

  # The lists R12 replaces, and one reordering (N13).
  @other_lists [
    ~w(usage-limit stall model-fallback),
    ~w(usage-limit stall model-fallback memory-pressure),
    ~w(usage-limit stall model-fallback pairing-freeze-lifted),
    ~w(usage-limit stall model-fallback pairing-freeze-lifted pairing-unfreeze-ignored
       recovery-enrolled admin-recovered root-recovery-enroll root-pairing-code),
    ~w(usage-limit stall model-fallback memory-pressure pairing-freeze-lifted
       pairing-unfreeze-ignored recovery-enrolled admin-recovered root-recovery-enroll
       root-pairing-code),
    ~w(stall usage-limit model-fallback memory-pressure pairing-freeze-lifted
       pairing-unfreeze-ignored recovery-enrolled admin-recovered root-recovery-enroll
       root-pairing-code memory-guard-stuck)
  ]

  test "T14: a fresh base gets the eleven-kind table, and one row of each kind inserts" do
    db = fresh_db()

    assert {:ok, [[sql]]} =
             DB.query(
               db,
               "SELECT sql FROM sqlite_master WHERE type='table' AND name='owner_alerts'"
             )

    assert sql =~ @check

    assert {:ok, [[0, "owner-alerts-v1-0114", _applied]]} =
             DB.query(db, "SELECT id, shape, appliedAt FROM owner_alert_migration")

    for {kind, index} <- Enum.with_index(@kinds) do
      assert {:ok, _} =
               DB.query(
                 db,
                 """
                 INSERT INTO owner_alerts
                   (alertId, kind, dedupeKey, ownerUserId, originSessionKey, sessionKey, turnSeq,
                    workItemId, anchorAt, title, body, state, createdAt, updatedAt, nextAttemptAt)
                 VALUES (?1, ?2, ?3, 'george', 'agent:main:george', ?4, ?5, ?6, ?7, 't', 'b',
                         'pending', 1, 1, 1)
                 """,
                 [
                   "oal_t14_#{index}",
                   kind,
                   "t14:#{kind}",
                   if(kind == "usage-limit", do: "agent:main:george"),
                   if(kind == "usage-limit", do: 1),
                   if(kind == "stall", do: "wi_t14"),
                   if(kind == "stall", do: 1)
                 ]
               )
    end

    assert {:ok, [[11]]} = DB.query(db, "SELECT COUNT(DISTINCT kind) FROM owner_alerts")
    assert {:error, _} = insert_kind(db, "not-a-kind")
    assert :ok = OwnerAlerts.ensure_schema(db)
  end

  test "N13: any other kind list is refused and nothing changes" do
    for list <- @other_lists do
      db = fresh_db()
      other = "CHECK (kind IN (" <> Enum.map_join(list, ",", &"'#{&1}'") <> "))"
      replace_table_check!(db, other)

      assert {:ok, [[before]]} =
               DB.query(
                 db,
                 "SELECT sql FROM sqlite_master WHERE type='table' AND name='owner_alerts'"
               )

      assert_raise Tightbeam.Schema.ShapeError, fn -> OwnerAlerts.ensure_schema(db) end

      assert {:ok, [[^before]]} =
               DB.query(
                 db,
                 "SELECT sql FROM sqlite_master WHERE type='table' AND name='owner_alerts'"
               )

      assert before =~ other
    end
  end

  defp fresh_db do
    db = :"owner_alerts_kinds_#{System.unique_integer([:positive])}"
    start_supervised!({DB, path: ":memory:", name: db}, id: db)
    :ok = ensure_all_schemas(db)
    db
  end

  defp insert_kind(db, kind) do
    DB.query(
      db,
      """
      INSERT INTO owner_alerts
        (alertId, kind, dedupeKey, ownerUserId, originSessionKey, title, body, state,
         createdAt, updatedAt, nextAttemptAt)
      VALUES ('oal_bad', ?1, 'bad', 'george', 'agent:main:george', 't', 'b', 'pending', 1, 1, 1)
      """,
      [kind]
    )
  end

  # Rebuild the empty table from its own DDL with only the kind CHECK changed,
  # keeping its indexes and the side-table row, as a database built from that
  # other DDL text would be.
  defp replace_table_check!(db, other) do
    {:ok, [[sql]]} =
      DB.query(db, "SELECT sql FROM sqlite_master WHERE type='table' AND name='owner_alerts'")

    {:ok, indexes} =
      DB.query(
        db,
        "SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name='owner_alerts' AND sql IS NOT NULL"
      )

    altered = String.replace(sql, @check, other)
    assert altered != sql

    :ok = DB.execute(db, "DROP TABLE owner_alerts")
    :ok = DB.execute(db, altered)
    for [index] <- indexes, do: :ok = DB.execute(db, index)
  end
end
