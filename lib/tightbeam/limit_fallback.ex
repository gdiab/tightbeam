defmodule Tightbeam.LimitFallback do
  @moduledoc """
  Durable state for the per-archetype limit-fallback switch (contract c v1.4,
  phase c1). This module owns the records; the evaluation and the switch
  itself run elsewhere and call in here inside their own transactions.

  - The configured fallback is the archetype's `[limit_fallback]`, read from
    the archetype as currently loaded (`Tightbeam.Archetypes.limit_fallback/1`).
    Nothing here retunes a session when a manifest is published.
  - A session may carry a fallback-off marker (R10): who set it, when, and an
    optional reason. A marked session is `restricted?/1`.
  - A switched session carries fallback-active state (R8a): since when, the
    tuple it was switched from, and the trigger. Any later tune of the session
    clears it; the switch sets it after its own swap, in the same transaction.
  - One evaluation row per session and trigger (a failed turn for T1, an
    incident for T2) holds the T1 claim hold and its single outcome. A row
    with no outcome is a standing hold: the session's lane claims nothing
    while it stands, and the outcome's commit releases it.
  - Withheld T1 outcomes are announced once per limit episode (R11, v1.4).
    The one withheld evaluation that filed an episode's notice and fact
    carries `withheldEpisode`, the seq of the episode's first failed turn;
    `UNIQUE (sessionKey, withheldEpisode)` lets no second one carry it.

  The schema objects are created by `Tightbeam.Schema` at the
  `limit-fallback-v1-0114` stamp transition, through `migrate_in_txn!/1`, and
  validated on every later boot through `validate_in_txn!/1`.
  """

  alias Tightbeam.{Archetypes, DB, EventLog, Model, Org}
  alias Tightbeam.DB.Txn
  alias Tightbeam.Schema.ShapeError

  @process "process:tightbeam"
  @attest_note_prefix "model-fallback applied "

  ## Schema

  # Columns are added with ALTER TABLE, which stores each definition's text in
  # the table's SQL; validation compares exactly that text.
  @sessions_off_column "limitFallbackOff TEXT CHECK (limitFallbackOff IS NULL OR (" <>
                         "json_valid(limitFallbackOff) " <>
                         "AND json_type(limitFallbackOff, '$.by') IS 'text' " <>
                         "AND json_type(limitFallbackOff, '$.at') IS 'integer' " <>
                         "AND json_type(limitFallbackOff, '$.reason') IN ('text', 'null')))"

  @sessions_active_column "fallbackActive TEXT CHECK (fallbackActive IS NULL OR (" <>
                            "json_valid(fallbackActive) " <>
                            "AND json_type(fallbackActive, '$.since') IS 'integer' " <>
                            "AND json_type(fallbackActive, '$.trigger') IS 'text' " <>
                            "AND json_type(fallbackActive, '$.from.harness') IS 'text' " <>
                            "AND json_type(fallbackActive, '$.from.model') IS 'text' " <>
                            "AND json_type(fallbackActive, '$.from.effort') IN ('text', 'null') " <>
                            "AND json_type(fallbackActive, '$.from.context') IN ('text', 'null')))"

  # R12: exactly one process-authored attest shape. The column carries the
  # whole rule; the table CHECK only gains the alternative that lets such a
  # row through, so existing rows are untouched by construction.
  @attests_process_column "byProcess TEXT NULL CHECK (byProcess IS NULL OR (" <>
                            "byProcess = '#{@process}' AND kind = 'progress' " <>
                            "AND bySession IS NULL AND byUser IS NULL AND verdictKind IS NULL " <>
                            "AND substr(note, 1, #{String.length(@attest_note_prefix)}) = " <>
                            "'#{@attest_note_prefix}'))"

  # The session-authored branch of the attests CHECK at the predecessor stamp
  # (`Tightbeam.Assignments` attests DDL, unchanged since cannot-proceed).
  @attests_session_branch ~r/\(kind IN \('progress', 'completion', 'surrender', 'cannot-proceed'\) AND bySession IS NOT NULL AND\s+byUser IS NULL AND verdictKind IS NULL\)/

  # Quota companion B2 (b0 ruling on asg_44e8352a, folded into this step): the
  # quota park's own fence instance names its open rate-limit-dead incident.
  # Only such a fence is kept by the quota-hold guard; any other fence on the
  # key (a close, shutdown or recovery fence) completes as before.
  @fences_quota_column "quotaIncidentId TEXT"

  @attests_process_branch "(kind = 'progress' AND bySession IS NULL AND byUser IS NULL " <>
                            "AND verdictKind IS NULL AND byProcess IS NOT NULL)"

  @evaluations_ddl """
  CREATE TABLE limit_fallback_evaluations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sessionKey  TEXT NOT NULL REFERENCES sessions(sessionKey),
    turnSeq     INTEGER REFERENCES turns(seq),
    incidentId  TEXT,
    heldAt      INTEGER CHECK (heldAt IS NULL OR heldAt >= 0),
    outcome     TEXT CHECK (outcome IN ('applied','withheld')),
    reason      TEXT CHECK (reason IS NULL OR length(reason) > 0),
    withheldEpisode INTEGER REFERENCES turns(seq),
    createdAt   INTEGER NOT NULL CHECK (createdAt >= 0),
    decidedAt   INTEGER CHECK (decidedAt IS NULL OR decidedAt >= 0),
    CHECK ((turnSeq IS NULL) != (incidentId IS NULL)),
    CHECK (heldAt IS NULL OR turnSeq IS NOT NULL),
    CHECK ((outcome IS NULL) = (decidedAt IS NULL)),
    CHECK (outcome IS NOT NULL OR heldAt IS NOT NULL),
    CHECK (outcome IS NOT NULL OR reason IS NULL),
    CHECK (outcome IS NULL OR (outcome = 'withheld') = (reason IS NOT NULL)),
    CHECK (withheldEpisode IS NULL OR (outcome = 'withheld' AND turnSeq IS NOT NULL)),
    UNIQUE (sessionKey, turnSeq),
    UNIQUE (sessionKey, incidentId),
    UNIQUE (sessionKey, withheldEpisode)
  )
  """

  @open_holds_ddl """
  CREATE INDEX limit_fallback_open_holds
  ON limit_fallback_evaluations (sessionKey) WHERE outcome IS NULL
  """

  @objects [
    {"table", "limit_fallback_evaluations", @evaluations_ddl},
    {"index", "limit_fallback_open_holds", @open_holds_ddl}
  ]

  @doc false
  def sessions_column_ddl, do: [@sessions_off_column, @sessions_active_column]

  @doc """
  Apply the limit-fallback objects inside the schema transaction that moves
  the stamp. The caller owns the exact predecessor stamp. A rewound stamp
  re-runs this over a database that already carries these exact objects; that
  is not corruption, and any other shape of them is refused by name.
  """
  @spec migrate_in_txn!(Txn.t()) :: :ok
  def migrate_in_txn!(%Txn{} = txn) do
    for column <- [@sessions_off_column, @sessions_active_column] do
      :ok = ensure_column!(txn, "sessions", column)
    end

    :ok = ensure_column!(txn, "attests", @attests_process_column)
    :ok = ensure_attests_process_branch!(txn)
    :ok = ensure_column!(txn, "harness_park_fences", @fences_quota_column)

    Enum.each(@objects, fn {type, name, sql} ->
      case Txn.q(txn, "SELECT sql FROM sqlite_master WHERE type=?1 AND name=?2", [type, name]) do
        [] -> :ok = Txn.exec(txn, sql)
        _present -> :ok
      end
    end)

    validate_in_txn!(txn)
  end

  @doc "Validate every limit-fallback object against its exact declared shape."
  @spec validate_in_txn!(Txn.t()) :: :ok
  def validate_in_txn!(%Txn{} = txn) do
    for column <- [@sessions_off_column, @sessions_active_column] do
      :ok = present!(txn, "sessions", column)
    end

    :ok = present!(txn, "attests", @attests_process_column)
    :ok = present!(txn, "harness_park_fences", @fences_quota_column)

    unless String.contains?(table_sql(txn, "attests"), normalize(@attests_process_branch)) do
      refuse!("attests CHECK lacks the process progress alternative")
    end

    Enum.each(@objects, fn {type, name, expected} ->
      case Txn.q(txn, "SELECT sql FROM sqlite_master WHERE type=?1 AND name=?2", [type, name]) do
        [[sql]] when is_binary(sql) ->
          unless normalize(sql) == normalize(expected),
            do: refuse!("#{type} #{name} has an unexpected shape: #{inspect(sql)}")

        rows ->
          refuse!("#{type} #{name} is missing or duplicated: #{inspect(rows)}")
      end
    end)

    :ok
  end

  defp ensure_column!(txn, table, column) do
    case column_state!(txn, table, column) do
      :absent -> Txn.exec(txn, "ALTER TABLE #{table} ADD COLUMN #{column}")
      :present -> :ok
    end
  end

  defp present!(txn, table, column) do
    case column_state!(txn, table, column) do
      :present -> :ok
      :absent -> refuse!("#{table}.#{column_name(column)} is missing")
    end
  end

  defp column_name(column), do: column |> String.split(" ", parts: 2) |> hd()

  # :absent when the column does not exist, :present when it exists with
  # exactly the declared definition, ending where the table's next column or
  # its closing parenthesis begins; anything else is refused.
  defp column_state!(txn, table, column) do
    [name | _] = String.split(column, " ", parts: 2)

    case Txn.q(
           txn,
           "SELECT type, \"notnull\", dflt_value, pk FROM pragma_table_info(?1) WHERE name=?2",
           [
             table,
             name
           ]
         ) do
      [] ->
        :absent

      [["TEXT", 0, nil, 0]] ->
        if Regex.match?(~r/#{Regex.escape(normalize(column))}\s*[,)]/, table_sql(txn, table)),
          do: :present,
          else: refuse!("#{table}.#{name} has an unexpected definition")

      rows ->
        refuse!("#{table}.#{name} has an unexpected column shape: #{inspect(rows)}")
    end
  end

  defp ensure_attests_process_branch!(txn) do
    [[sql]] = Txn.q(txn, "SELECT sql FROM sqlite_master WHERE type='table' AND name='attests'")

    cond do
      String.contains?(normalize(sql), normalize(@attests_process_branch)) ->
        :ok

      length(Regex.scan(@attests_session_branch, sql)) == 1 ->
        # The predecessor's session-authored branch, followed by one new
        # alternative. Adding an alternative only admits rows; no stored row
        # changes, so the table needs no rebuild (the same in-place CHECK
        # edit the session-identity migration made to this table).
        updated =
          Regex.replace(@attests_session_branch, sql, fn branch ->
            branch <> "\n      OR\n      " <> @attests_process_branch
          end)

        [[version]] = Txn.q(txn, "PRAGMA schema_version")
        :ok = Txn.exec(txn, "PRAGMA writable_schema = ON")

        Txn.q(txn, "UPDATE sqlite_master SET sql=?1 WHERE type='table' AND name='attests'", [
          updated
        ])

        :ok = Txn.exec(txn, "PRAGMA schema_version = #{version + 1}")
        :ok = Txn.exec(txn, "PRAGMA writable_schema = RESET")
        :ok

      true ->
        refuse!("attests CHECK does not carry exactly one session-authored branch")
    end
  end

  defp table_sql(txn, table) do
    case Txn.q(txn, "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1", [table]) do
      [[sql]] when is_binary(sql) -> normalize(sql)
      rows -> refuse!("table #{table} is missing: #{inspect(rows)}")
    end
  end

  defp normalize(sql),
    do:
      sql
      |> String.replace("\"", "")
      |> String.replace(~r/\s+/, " ")
      |> String.replace("( ", "(")
      |> String.replace(" )", ")")
      |> String.trim()
      |> String.trim_trailing(";")

  defp refuse!(detail),
    do: raise(ShapeError, message: "incompatible_limit_fallback_schema: #{detail}")

  ## Configuration (R1, R2)

  @doc """
  The configured fallback of the session's archetype as currently loaded, or
  nil when it declares none (R3: behaviour is then exactly as without this).
  """
  @spec configured(Org.session() | String.t()) :: Archetypes.limit_fallback() | nil
  def configured(%{archetype: archetype}), do: configured(archetype)
  def configured(archetype) when is_binary(archetype), do: Archetypes.limit_fallback(archetype)

  ## Restriction marker (R10)

  @doc "Whether the session carries the fallback-off marker."
  @spec restricted?(Org.session()) :: boolean()
  def restricted?(%{limit_fallback_off: marker}), do: not is_nil(marker)

  @doc """
  Set (`:off`) or clear (`:on`) the fallback-off marker. `actor` is the
  principal of the tune or spawn that sets it. Records one lifecycle event.
  Returns the updated session.
  """
  @spec set_restriction_in_txn(Txn.t(), String.t(), :off | :on, String.t(), String.t() | nil) ::
          Org.session()
  def set_restriction_in_txn(%Txn{} = txn, session_key, :off, actor, reason)
      when is_binary(actor) and actor != "" and (is_nil(reason) or is_binary(reason)) do
    marker = restriction_marker(actor, reason)
    session = Org.set_limit_fallback_off_in_txn(txn, session_key, marker)

    EventLog.lifecycle_in_txn(
      txn,
      "limit-fallback-off",
      session_key,
      JSON.encode!(%{"by" => actor, "reason" => marker.reason})
    )

    session
  end

  def set_restriction_in_txn(%Txn{} = txn, session_key, :on, actor, _reason)
      when is_binary(actor) and actor != "" do
    session = Org.set_limit_fallback_off_in_txn(txn, session_key, nil)

    EventLog.lifecycle_in_txn(
      txn,
      "limit-fallback-on",
      session_key,
      JSON.encode!(%{"by" => actor})
    )

    session
  end

  @doc """
  Record the lifecycle event of a marker a spawn stored with its new row
  (`spawn --limit-fallback off`). Nothing for an unrestricted spawn.
  """
  @spec record_spawn_restriction_in_txn(Txn.t(), Org.session()) :: :ok
  def record_spawn_restriction_in_txn(%Txn{}, %{limit_fallback_off: nil}), do: :ok

  def record_spawn_restriction_in_txn(%Txn{} = txn, %{
        session_key: session_key,
        limit_fallback_off: %{by: by, reason: reason}
      }) do
    EventLog.lifecycle_in_txn(
      txn,
      "limit-fallback-off",
      session_key,
      JSON.encode!(%{"by" => by, "reason" => reason})
    )
  end

  @doc false
  # The marker a spawn stores with the new row (Org.create_in_txn/2).
  @spec restriction_marker(String.t(), String.t() | nil) :: map()
  def restriction_marker(actor, reason) do
    reason =
      case reason do
        value when is_binary(value) -> if String.trim(value) == "", do: nil, else: value
        nil -> nil
      end

    %{by: actor, at: System.system_time(:millisecond), reason: reason}
  end

  ## Fallback-active (R8a)

  @doc "Whether the session is on its configured fallback after an applied switch."
  @spec fallback_active?(Org.session()) :: boolean()
  def fallback_active?(%{fallback_active: state}), do: not is_nil(state)

  @doc """
  Mark the session fallback-active. Phase 2's switch calls this inside the
  swap transaction (its `on_swap_interlock`), after the swap, so the tune
  path's own clear does not undo it. `from` is the pre-switch tuple; `trigger`
  is `{:turn, seq}` or `{:incident, id}`. Returns the updated session.
  """
  @spec set_fallback_active_in_txn(Txn.t(), String.t(), %{
          since: non_neg_integer(),
          from: %{harness: String.t(), model: Model.t()},
          trigger: {:turn, pos_integer()} | {:incident, String.t()}
        }) :: Org.session()
  def set_fallback_active_in_txn(%Txn{} = txn, session_key, %{
        since: since,
        from: %{harness: harness, model: %Model{} = model},
        trigger: trigger
      })
      when is_integer(since) and since >= 0 and is_binary(harness) do
    Org.set_fallback_active_in_txn(txn, session_key, %{
      since: since,
      from: %{harness: harness, model: model},
      trigger: trigger_ref(trigger)
    })
  end

  @doc """
  Clear fallback-active. Every tune that changes the session's selection calls
  this in its own commit, before any swap interlock runs.
  """
  @spec clear_fallback_active_in_txn(Txn.t(), String.t()) :: Org.session()
  def clear_fallback_active_in_txn(%Txn{} = txn, session_key),
    do: Org.set_fallback_active_in_txn(txn, session_key, nil)

  @doc "The stored text of a trigger: `turn:<seq>` or `incident:<id>`."
  @spec trigger_ref({:turn, pos_integer()} | {:incident, String.t()}) :: String.t()
  def trigger_ref({:turn, seq}) when is_integer(seq) and seq > 0, do: "turn:#{seq}"
  def trigger_ref({:incident, id}) when is_binary(id) and id != "", do: "incident:" <> id

  ## Claim hold and outcomes (R5, R11)

  @type trigger :: {:turn, pos_integer()} | {:incident, String.t()}
  @type evaluation :: %{
          id: pos_integer(),
          session_key: String.t(),
          trigger: trigger(),
          held_at: non_neg_integer() | nil,
          outcome: String.t() | nil,
          reason: String.t() | nil,
          withheld_episode: pos_integer() | nil,
          created_at: non_neg_integer(),
          decided_at: non_neg_integer() | nil
        }

  @doc """
  Set the T1 claim hold for a failed turn, inside that turn's terminal
  transaction. A trigger already evaluated or already held is not held again:
  the result says which, so a re-entered evaluation yields no second outcome.
  """
  @spec hold_in_txn(Txn.t(), String.t(), pos_integer()) ::
          {:held, evaluation()} | {:already_held, evaluation()} | {:decided, evaluation()}
  def hold_in_txn(%Txn{} = txn, session_key, turn_seq)
      when is_binary(session_key) and is_integer(turn_seq) and turn_seq > 0 do
    now = System.system_time(:millisecond)

    Txn.q(
      txn,
      """
      INSERT INTO limit_fallback_evaluations (sessionKey, turnSeq, heldAt, createdAt)
      VALUES (?1, ?2, ?3, ?3)
      ON CONFLICT (sessionKey, turnSeq) DO NOTHING
      """,
      [session_key, turn_seq, now]
    )

    inserted? = Txn.changes(txn) == 1
    evaluation = evaluation_in_txn(txn, session_key, {:turn, turn_seq})

    cond do
      inserted? -> {:held, evaluation}
      is_nil(evaluation.outcome) -> {:already_held, evaluation}
      true -> {:decided, evaluation}
    end
  end

  @doc "Whether the session has a standing claim hold (an evaluation with no outcome)."
  @spec held?(DB.server(), String.t()) :: boolean()
  def held?(db \\ DB, session_key) do
    {:ok, rows} =
      DB.query(
        db,
        "SELECT 1 FROM limit_fallback_evaluations WHERE sessionKey=?1 AND outcome IS NULL LIMIT 1",
        [session_key]
      )

    rows != []
  end

  @doc """
  Commit the one outcome of an evaluation, releasing its hold if it had one.
  `{:recorded, evaluation}` the first time; `{:duplicate, evaluation}` when the
  trigger already has an outcome, in which case nothing is written and the
  caller emits nothing (R5 exactly once; R14 one lifecycle event per trigger). Call it in the
  transaction that writes the outcome's other records: the swap transaction
  for `:applied`, the withhold transaction for `{:withheld, reason}`.
  """
  @spec record_outcome_in_txn(Txn.t(), String.t(), trigger(), :applied | {:withheld, String.t()}) ::
          {:recorded, evaluation()} | {:duplicate, evaluation()}
  def record_outcome_in_txn(%Txn{} = txn, session_key, trigger, outcome) do
    {value, reason} =
      case outcome do
        :applied -> {"applied", nil}
        {:withheld, reason} when is_binary(reason) and reason != "" -> {"withheld", reason}
      end

    now = System.system_time(:millisecond)
    {column, ref} = trigger_column(trigger)

    case evaluation_in_txn(txn, session_key, trigger) do
      nil ->
        Txn.q(
          txn,
          """
          INSERT INTO limit_fallback_evaluations
            (sessionKey, #{column}, outcome, reason, createdAt, decidedAt)
          VALUES (?1, ?2, ?3, ?4, ?5, ?5)
          """,
          [session_key, ref, value, reason, now]
        )

        {:recorded, evaluation_in_txn(txn, session_key, trigger)}

      %{outcome: nil, id: id} ->
        Txn.q(
          txn,
          """
          UPDATE limit_fallback_evaluations SET outcome=?2, reason=?3, decidedAt=?4
          WHERE id=?1 AND outcome IS NULL
          """,
          [id, value, reason, now]
        )

        if Txn.changes(txn) != 1, do: raise("limit fallback outcome race on evaluation #{id}")
        {:recorded, evaluation_in_txn(txn, session_key, trigger)}

      decided ->
        {:duplicate, decided}
    end
  end

  @doc "The evaluation of one trigger, or nil."
  @spec evaluation_in_txn(Txn.t(), String.t(), trigger()) :: evaluation() | nil
  def evaluation_in_txn(%Txn{} = txn, session_key, trigger) do
    {column, ref} = trigger_column(trigger)

    case Txn.q(
           txn,
           "SELECT #{evaluation_columns()} FROM limit_fallback_evaluations WHERE sessionKey=?1 AND #{column}=?2",
           [session_key, ref]
         ) do
      [row] -> to_evaluation(row)
      [] -> nil
    end
  end

  @doc """
  Claim the announcement of a limit episode for one withheld T1 evaluation,
  in the transaction that commits that outcome (R11, v1.4). `episode` is the
  seq of the episode's first failed turn
  (`Tightbeam.HarnessHealth.limit_episode_first_seq_in_txn/3`). `true` when
  no evaluation of the session has announced that episode yet: this one now
  carries it and its outcome files the episode's notice and fact. `false`
  otherwise; the caller then records the outcome and its lifecycle event
  only. The claim is a stored column, so it holds across restarts, and it
  reads nothing of the owner-alert setting.
  """
  @spec claim_withheld_episode_in_txn(Txn.t(), evaluation(), pos_integer()) :: boolean()
  def claim_withheld_episode_in_txn(
        %Txn{} = txn,
        %{id: id, session_key: session_key, outcome: "withheld", trigger: {:turn, _seq}},
        episode
      )
      when is_integer(episode) and episode > 0 do
    Txn.q(
      txn,
      """
      UPDATE limit_fallback_evaluations SET withheldEpisode=?2
      WHERE id=?1 AND withheldEpisode IS NULL
        AND NOT EXISTS (
          SELECT 1 FROM limit_fallback_evaluations
          WHERE sessionKey=?3 AND withheldEpisode=?2
        )
      """,
      [id, episode, session_key]
    )

    Txn.changes(txn) == 1
  end

  @doc """
  Every standing hold. At gateway start, before any lane claims, phase 2
  releases each with a withheld `switch-failed:interrupted` outcome.
  """
  @spec outstanding_holds_in_txn(Txn.t()) :: [evaluation()]
  def outstanding_holds_in_txn(%Txn{} = txn) do
    txn
    |> Txn.q(
      "SELECT #{evaluation_columns()} FROM limit_fallback_evaluations WHERE outcome IS NULL ORDER BY id"
    )
    |> Enum.map(&to_evaluation/1)
  end

  defp trigger_column({:turn, seq}) when is_integer(seq) and seq > 0, do: {"turnSeq", seq}

  defp trigger_column({:incident, id}) when is_binary(id) and id != "",
    do: {"incidentId", id}

  defp evaluation_columns,
    do:
      "id, sessionKey, turnSeq, incidentId, heldAt, outcome, reason, withheldEpisode, " <>
        "createdAt, decidedAt"

  defp to_evaluation([
         id,
         session_key,
         turn_seq,
         incident_id,
         held_at,
         outcome,
         reason,
         withheld_episode,
         created_at,
         decided_at
       ]) do
    %{
      id: id,
      session_key: session_key,
      trigger: if(turn_seq, do: {:turn, turn_seq}, else: {:incident, incident_id}),
      held_at: held_at,
      outcome: outcome,
      reason: reason,
      withheld_episode: withheld_episode,
      created_at: created_at,
      decided_at: decided_at
    }
  end

  ## Progress record (R12)

  @doc "The note prefix the attests CHECK admits for the process progress attest."
  @spec attest_note_prefix() :: String.t()
  def attest_note_prefix, do: @attest_note_prefix

  @doc "The only principal that may author the process progress attest."
  @spec process_principal() :: String.t()
  def process_principal, do: @process
end
