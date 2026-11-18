defmodule Tightbeam.LimitFallback.Outcome do
  @moduledoc """
  The records of one limit-fallback evaluation's single outcome (contract c
  v1.4, phase c1). Every function here runs inside the transaction that commits
  the outcome: the swap transaction's `on_swap_interlock` for an applied
  switch, or the withhold transaction. The evaluation and the switch itself
  run in `Tightbeam.Gateway`.

  - R9a: the failed turn is classified from its own records.
  - R9b: its replay vehicles are the existing ones, written here instead of in
    its terminal transaction: as today for a withheld outcome or a `replayed`
    turn, never for an `unknown_effect` turn of an applied switch.
  - R11-R15: the outcome's records: one process progress attest per open
    assignment (applied only), one notice per distinct delivery owner, one
    process-only fact, one lifecycle event and one owner alert.
  - R11 (v1.4): a withheld outcome's notices, fact and alert are emitted once
    per limit episode of the session, the episode of
    `Tightbeam.HarnessHealth.limit_episode_first_seq_in_txn/3`. Every
    evaluation still writes its outcome and its lifecycle event. The notices
    and fact are gated by the episode claim on the evaluation record
    (`LimitFallback.claim_withheld_episode_in_txn/3`), never by the alert
    setting; the alert is deduped by its own episode `dedupeKey`.

  `LimitFallback.record_outcome_in_txn/4` decides whether this is the first
  outcome of its trigger; a duplicate writes nothing.
  """

  alias Tightbeam.{
    Assignments,
    ConditionFacts,
    EventLog,
    HarnessHealth,
    LimitFallback,
    Model,
    Org,
    Wakes
  }

  alias Tightbeam.DB.Txn

  defmodule Duplicate do
    @moduledoc false
    defexception message: "limit fallback trigger already has an outcome"
  end

  @process "process:tightbeam"
  @class "rate-limit-dead"

  @type disposition :: :replayed | :unknown_effect

  ## Failed-turn disposition (R9a, R9b)

  @doc """
  Classify the failed turn from its own records (R9a). `:replayed` when no
  `prompt_dispatched` event exists for that turn, or when it was dispatched
  but recorded no tool call and no assistant message; `:unknown_effect`
  otherwise. The stage stored on `harness_turn_error` is keyed by session and
  is never read here.
  """
  @spec classify_in_txn(Txn.t(), pos_integer()) :: disposition()
  def classify_in_txn(%Txn{} = txn, turn_seq) when is_integer(turn_seq) and turn_seq > 0 do
    cond do
      not dispatched?(txn, turn_seq) -> :replayed
      tool_calls?(txn, turn_seq) or assistant_messages?(txn, turn_seq) -> :unknown_effect
      true -> :replayed
    end
  end

  defp dispatched?(txn, turn_seq),
    do:
      Txn.q(
        txn,
        "SELECT 1 FROM turn_lifecycle_events WHERE turnSeq=?1 AND kind='prompt_dispatched' LIMIT 1",
        [turn_seq]
      ) != []

  defp tool_calls?(txn, turn_seq),
    do: Txn.q(txn, "SELECT 1 FROM tool_calls WHERE turnSeq=?1 LIMIT 1", [turn_seq]) != []

  defp assistant_messages?(txn, turn_seq),
    do:
      Txn.q(
        txn,
        """
        SELECT 1 FROM turns t
        JOIN messages m ON m.sessionKey=t.sessionKey AND m.replyToMessageId=t.messageId
        WHERE t.seq=?1 AND m.role='assistant'
        LIMIT 1
        """,
        [turn_seq]
      ) != []

  @doc """
  Write the failed turn's existing replay vehicles, exactly as its terminal
  transaction would have: the rate-limit retry lineage of a wake turn
  (`Wakes.preserve_failed_intent_for_terminal_in_txn/2`, due at the existing
  backoff from the turn's end) and the `health_redelivery_attempts` row of
  its message. Both are idempotent, so a withhold after a `replayed`
  classification writes nothing twice.
  """
  @spec preserve_failed_intent_in_txn(Txn.t(), pos_integer()) :: :ok
  def preserve_failed_intent_in_txn(%Txn{} = txn, turn_seq) do
    Wakes.preserve_failed_intent_for_terminal_in_txn(txn, turn_seq)
    :ok = Wakes.record_health_redelivery_source_in_txn(txn, turn_seq, @class)
  end

  @doc """
  The statement the new engine receives with the handoff when the failed turn
  had unknown effects and was not replayed (R9b).
  """
  @spec unknown_effect_statement_in_txn(Txn.t(), pos_integer()) :: String.t()
  def unknown_effect_statement_in_txn(%Txn{} = txn, turn_seq) do
    [[request_ref, message_id]] =
      Txn.q(txn, "SELECT requestRef, messageId FROM turns WHERE seq=?1", [turn_seq])

    "## Limit fallback: a failed turn was not replayed\n\n" <>
      "This session was moved to this engine after its turn #{turn_seq} failed on a usage " <>
      "limit. That turn's original request reference is #{request_ref || "none"} " <>
      "(message #{message_id || "none"}). It was dispatched and recorded tool calls or " <>
      "replies, so it may have had effects, and it was NOT replayed. Before acting on that " <>
      "request, re-derive its state from the records (the transcript, tool calls, " <>
      "assignments and attests) and check whether its effects already happened."
  end

  ## Applied (R5, R8a, R9b, R12-R15)

  @doc """
  Commit the applied outcome inside the swap transaction, after the swap.
  `ctx` carries `:session_key`, `:turn_seq`, `:evidence`, `:disposition`, the
  pre-switch `:from` (`harness`, `model`, `provider`) and the configured `:to`
  (`harness`, `model`). Raises `Duplicate` when the trigger already has an
  outcome, which rolls the swap back: one trigger never switches twice.
  """
  @spec applied_in_txn(Txn.t(), map()) :: :ok
  def applied_in_txn(%Txn{} = txn, %{session_key: session_key, turn_seq: turn_seq} = ctx) do
    trigger = {:turn, turn_seq}

    case LimitFallback.record_outcome_in_txn(txn, session_key, trigger, :applied) do
      {:recorded, _evaluation} -> :ok
      {:duplicate, _evaluation} -> raise Duplicate
    end

    since = System.system_time(:millisecond)

    LimitFallback.set_fallback_active_in_txn(txn, session_key, %{
      since: since,
      from: %{harness: ctx.from.harness, model: ctx.from.model},
      trigger: trigger
    })

    # R12: the readback is the sessions row as the swap left it.
    readback = Org.get_in_txn(txn, session_key)

    if ctx.disposition == :unknown_effect,
      do: :ok = Wakes.settle_unreplayed_failure_in_txn(txn, turn_seq)

    assignments = open_assignments_in_txn(txn, session_key)

    facts =
      txn
      |> session_facts_in_txn(session_key, turn_seq)
      |> Map.merge(%{
        outcome: :applied,
        since: since,
        provider: ctx.from.provider,
        from: %{harness: ctx.from.harness, model: ctx.from.model},
        to: ctx.to,
        readback: %{harness: readback.harness, model: readback.model},
        evidence: ctx.evidence,
        disposition: ctx.disposition,
        replay: replay_in_txn(txn, turn_seq, ctx.disposition),
        assignments: assignments
      })

    note = attest_note(facts)

    Enum.each(assignments, fn assignment ->
      Assignments.record_model_fallback_attest_in_txn(txn, assignment.id, note)
    end)

    record_in_txn(txn, facts)
  end

  ## Withheld (R5, R11, R13-R15)

  @doc """
  Commit a withheld outcome: the trigger's one outcome with its named reason,
  the failed turn's replay vehicles as today, and its lifecycle event. The
  first withheld outcome of the session's limit episode also files the
  episode's notices and fact; a later one in the same episode files neither
  (R11, v1.4). Each offers the episode's owner alert, which its `dedupeKey`
  keeps to one. No progress attest (R11). `:duplicate` when the trigger
  already has an outcome; nothing is written then.
  """
  @spec withheld_in_txn(Txn.t(), String.t(), pos_integer(), String.t()) ::
          :recorded | :duplicate
  def withheld_in_txn(%Txn{} = txn, session_key, turn_seq, reason) do
    case LimitFallback.record_outcome_in_txn(
           txn,
           session_key,
           {:turn, turn_seq},
           {:withheld, reason}
         ) do
      {:duplicate, _evaluation} ->
        :duplicate

      {:recorded, evaluation} ->
        :ok = preserve_failed_intent_in_txn(txn, turn_seq)
        session = Org.get_in_txn(txn, session_key)
        episode = HarnessHealth.limit_episode_first_seq_in_txn(txn, session_key, turn_seq)

        facts =
          txn
          |> session_facts_in_txn(session_key, turn_seq)
          |> Map.merge(%{
            outcome: :withheld,
            since: System.system_time(:millisecond),
            provider: session.provider,
            from: %{harness: session.harness, model: session.model},
            configured: LimitFallback.configured(session),
            reason: reason,
            replay: replay_in_txn(txn, turn_seq, :replayed),
            assignments: open_assignments_in_txn(txn, session_key),
            episode: episode,
            announce: LimitFallback.claim_withheld_episode_in_txn(txn, evaluation, episode)
          })

        :ok = record_in_txn(txn, facts)
        :recorded
    end
  end

  @doc """
  The last resort when a withhold's records cannot be written: commit the
  outcome alone, with the failed turn's replay vehicles and a lifecycle event
  naming the failure, so no hold outlives its evaluation. It claims no limit
  episode, so the episode's next withheld outcome still announces it.
  """
  @spec withheld_bare_in_txn(Txn.t(), String.t(), pos_integer(), String.t(), String.t()) ::
          :recorded | :duplicate
  def withheld_bare_in_txn(%Txn{} = txn, session_key, turn_seq, reason, failure) do
    case LimitFallback.record_outcome_in_txn(
           txn,
           session_key,
           {:turn, turn_seq},
           {:withheld, reason}
         ) do
      {:duplicate, _evaluation} ->
        :duplicate

      {:recorded, _evaluation} ->
        :ok = preserve_failed_intent_in_txn(txn, turn_seq)

        EventLog.lifecycle_in_txn(
          txn,
          "session-model-fallback-withheld",
          session_key,
          JSON.encode!(%{
            "session" => session_key,
            "trigger" => LimitFallback.trigger_ref({:turn, turn_seq}),
            "class" => @class,
            "reason" => reason,
            "recordsFailed" => failure
          })
        )

        :recorded
    end
  end

  ## Shared records

  # An applied outcome always announces. A withheld one announces (notices
  # and fact) only when it claimed its limit episode.
  defp record_in_txn(txn, facts) do
    kind = fact_kind(facts.outcome)
    announce? = Map.get(facts, :announce, true)

    notices =
      if announce? do
        notices = schedule_notices_in_txn(txn, facts)

        case ConditionFacts.file_in_txn(txn, %{
               kind: kind,
               scope: facts.session_key,
               origin: @process,
               owner_user_id: facts.owner_user_id
             }) do
          %{fact_id: _} -> :ok
          {:error, error} -> raise ArgumentError, "#{kind} fact refused: #{inspect(error)}"
        end

        notices
      else
        []
      end

    EventLog.lifecycle_in_txn(
      txn,
      kind,
      facts.session_key,
      JSON.encode!(lifecycle_detail(facts, notices))
    )

    :ok =
      Tightbeam.OwnerAlerts.model_fallback_in_txn(txn, %{
        session_key: facts.session_key,
        turn_seq: facts.turn_seq,
        dedupe_ref: alert_dedupe_ref(facts),
        title: alert_title(facts),
        body: notice_text(facts, facts.assignments)
      })

    :ok
  end

  defp alert_dedupe_ref(%{outcome: :applied, trigger_ref: trigger_ref}),
    do: {:applied, trigger_ref}

  defp alert_dedupe_ref(%{outcome: :withheld, episode: episode}), do: {:withheld, episode}

  defp fact_kind(:applied), do: "session-model-fallback-applied"
  defp fact_kind(:withheld), do: "session-model-fallback-withheld"

  defp session_facts_in_txn(txn, session_key, turn_seq) do
    [[display_name, owner_user_id]] =
      Txn.q(txn, "SELECT displayName, ownerUserId FROM sessions WHERE sessionKey=?1", [
        session_key
      ])

    %{
      session_key: session_key,
      display_name: display_name || session_key,
      owner_user_id: owner_user_id,
      turn_seq: turn_seq,
      trigger_ref: LimitFallback.trigger_ref({:turn, turn_seq})
    }
  end

  defp open_assignments_in_txn(txn, session_key) do
    txn
    |> Txn.q(
      "SELECT id, subject FROM assignments WHERE holderKey=?1 AND state='open' ORDER BY openedAt, id",
      [session_key]
    )
    |> Enum.map(fn [id, subject] -> %{id: id, subject: subject} end)
  end

  # When the existing vehicle replays the failed turn (the owner is told when,
  # so nobody is left guessing): the rate-limit retry wake of a wake turn is
  # due at its existing backoff; a message turn's redelivery row is consumed
  # by the session's next turn that completes normally.
  defp replay_in_txn(_txn, _turn_seq, :unknown_effect), do: :not_replayed

  defp replay_in_txn(txn, turn_seq, :replayed) do
    case Txn.q(
           txn,
           """
           SELECT r.retryWakeId, w.dueAt FROM wake_retry_attempts r
           JOIN wakes w ON w.wakeId=r.retryWakeId
           WHERE r.sourceTurnSeq=?1 AND w.state='pending'
           ORDER BY w.dueAt, w.wakeId LIMIT 1
           """,
           [turn_seq]
         ) do
      [[wake_id, due_at]] ->
        {:retry_wake, wake_id, due_at}

      [] ->
        case Txn.q(
               txn,
               """
               SELECT 1 FROM health_redelivery_attempts
               WHERE sourceTurnSeq=?1 AND redeliveryTurnSeq IS NULL AND parentSessionKey IS NULL
               """,
               [turn_seq]
             ) do
          [_ | _] -> :next_normal_turn
          [] -> :no_vehicle
        end
    end
  end

  ## Notices (R13)

  defp schedule_notices_in_txn(txn, facts) do
    class = notice_class(facts)
    now = System.system_time(:millisecond)

    txn
    |> notice_recipients_in_txn(facts)
    |> Enum.map(fn {recipient, assignments} ->
      wake_id = notice_wake_id(facts, recipient)

      input =
        %{
          wake_id: wake_id,
          session_key: recipient,
          origin: @process,
          prompt: notice_text(facts, assignments),
          due_at: now,
          class: class
        }
        |> then(fn input ->
          case assignments do
            [%{id: assignment_id} | _] -> Map.put(input, :assignment_id, assignment_id)
            [] -> input
          end
        end)

      Wakes.schedule_in_txn(txn, input)
      wake_id
    end)
  end

  defp notice_class(%{outcome: :withheld}), do: "blocker"
  defp notice_class(%{outcome: :applied, disposition: :replayed}), do: "fyi"
  defp notice_class(%{outcome: :applied, disposition: :unknown_effect}), do: "input-needed"

  # One notice per distinct delivery owner of the session's open assignments,
  # in assignment order; with none, the session owner's Main.
  defp notice_recipients_in_txn(txn, facts) do
    main = Org.personal_session_key(facts.owner_user_id)

    case facts.assignments do
      [] ->
        [{main, []}]

      assignments ->
        assignments
        |> Enum.reduce([], fn assignment, groups ->
          owner =
            case Wakes.delivery_owner_in_txn(txn, assignment.id) do
              {:ok, recipient} -> recipient
              {:error, _} -> main
            end

          case List.keyfind(groups, owner, 0) do
            nil -> groups ++ [{owner, [assignment]}]
            {^owner, listed} -> List.keyreplace(groups, owner, 0, {owner, listed ++ [assignment]})
          end
        end)
    end
    |> Enum.filter(fn {recipient, _assignments} ->
      Txn.q(txn, "SELECT 1 FROM sessions WHERE sessionKey=?1 AND state='active'", [recipient]) ==
        [[1]]
    end)
  end

  defp notice_wake_id(facts, recipient) do
    digest =
      :crypto.hash(:sha256, JSON.encode!([facts.session_key, facts.trigger_ref, recipient]))
      |> Base.encode16(case: :lower)
      |> binary_part(0, 32)

    "w_limit_fallback_" <> digest
  end

  @doc false
  @spec notice_text(map(), [map()]) :: String.t()
  def notice_text(%{outcome: :applied} = facts, assignments) do
    """
    Session #{facts.display_name} (#{facts.session_key}) is now on its limit fallback #{engine(facts.to)}, since #{iso(facts.since)}.

    Why: its turn #{facts.turn_seq} failed on provider #{facts.provider} (#{engine(facts.from)}) with a usage limit: class #{@class}, typed evidence #{facts.evidence}.

    Failed turn #{facts.turn_seq}: #{disposition_sentence(facts)}

    The session stays on the fallback after the limit resets; nothing switches it back automatically. To switch back, at a natural boundary, run:
    #{switch_back_command(facts.session_key, facts.from)}

    #{assignment_lines(assignments)}

    This is a notification, not staffing or a transfer: the session, its assignments and their holder are unchanged.
    """
    |> String.trim_trailing()
  end

  def notice_text(%{outcome: :withheld} = facts, assignments) do
    """
    Session #{facts.display_name} (#{facts.session_key}) could not switch to its limit fallback#{configured_suffix(facts)}: #{reason_sentence(facts.reason)} (reason #{facts.reason}), at #{iso(facts.since)}.

    Why it was evaluated: its turn #{facts.turn_seq} failed on provider #{facts.provider} (#{engine(facts.from)}) with a usage limit: class #{@class}.

    The session stays on #{engine(facts.from)}. Failed turn #{facts.turn_seq} is handled as before: #{replay_sentence(facts.replay)}

    #{assignment_lines(assignments)}

    This is a notification, not staffing or a transfer: the session, its assignments and their holder are unchanged.
    """
    |> String.trim_trailing()
  end

  defp configured_suffix(%{configured: %{model: %Model{} = model}}),
    do: " (#{model_name(model)}/#{model.effort || "none"})"

  defp configured_suffix(_facts), do: ""

  defp disposition_sentence(%{disposition: :replayed, replay: replay}),
    do:
      "no tool call or reply was recorded for it, so it is replayed once on the fallback. " <>
        replay_sentence(replay)

  defp disposition_sentence(%{disposition: :unknown_effect}),
    do:
      "it was dispatched and recorded tool calls or replies, so it may have had effects and " <>
        "was NOT replayed. The session was told to re-derive its state from the records before " <>
        "acting on that request; decide whether it must be redone."

  defp replay_sentence({:retry_wake, wake_id, due_at}),
    do: "its existing rate-limit retry wake #{wake_id} carries it, due at #{iso(due_at)}."

  defp replay_sentence(:next_normal_turn),
    do:
      "its existing health redelivery carries it, after this session's next turn that " <>
        "completes normally."

  defp replay_sentence(:no_vehicle), do: "no existing retry or redelivery carries it."
  defp replay_sentence(:not_replayed), do: "it is not replayed."

  defp reason_sentence("restricted"), do: "the session carries the limit-fallback off marker"
  defp reason_sentence("main"), do: "the session is its owner's personal Main"

  defp reason_sentence("already-on-fallback"),
    do: "the session is already on its fallback after an earlier switch"

  defp reason_sentence("unqualified:R4.1"),
    do: "its archetype no longer declares a limit fallback"

  defp reason_sentence("unqualified:R1-harness"),
    do:
      "the archetype's fallback names a harness other than the one the catalog routes its " <>
        "model to on this host"

  defp reason_sentence("unqualified:R4.5"),
    do: "the fallback runs on the same harness or the same provider as the failed turn"

  defp reason_sentence("unqualified:R4.6"),
    do:
      "the fallback's harness has an open usage-limit, authentication or credential incident " <>
        "on this host"

  defp reason_sentence("unqualified:R4.7"),
    do:
      "the fallback did not pass the harness-change checks on this host (credential, catalog " <>
        "or readiness)"

  defp reason_sentence("switch-failed:" <> failure),
    do: "the switch to the fallback failed (#{failure}) and nothing was swapped"

  defp reason_sentence(reason), do: reason

  defp assignment_lines([]), do: "Open assignments of the session: none."

  defp assignment_lines(assignments) do
    "Open assignments of the session:\n" <>
      Enum.map_join(assignments, "\n", fn %{id: id, subject: subject} ->
        "- #{id}: #{subject}"
      end)
  end

  defp alert_title(%{outcome: :applied, display_name: name}),
    do: "#{name} switched to its fallback model"

  defp alert_title(%{outcome: :withheld, display_name: name}),
    do: "#{name} could not switch to a fallback model"

  @doc "The exact command that switches the session back to its pre-switch engine."
  @spec switch_back_command(String.t(), %{harness: String.t(), model: Model.t()}) :: String.t()
  def switch_back_command(session_key, %{harness: harness, model: %Model{} = model}) do
    [
      "tightbeam tune --session",
      shell_arg(session_key),
      "--harness",
      shell_arg(harness),
      "--model",
      shell_arg(model.family)
    ]
    |> Kernel.++(if model.effort, do: ["--effort", shell_arg(model.effort)], else: [])
    |> Kernel.++(if model.context, do: ["--context", shell_arg(model.context)], else: [])
    |> Enum.join(" ")
  end

  defp shell_arg(value) do
    if Regex.match?(~r/\A[A-Za-z0-9_.:\/@%+=-]+\z/, value),
      do: value,
      else: "'" <> String.replace(value, "'", "'\\''") <> "'"
  end

  ## Progress record (R12) and lifecycle (R14)

  defp attest_note(facts) do
    LimitFallback.attest_note_prefix() <>
      Enum.join(
        [
          "session=#{facts.session_key}",
          "from=#{engine(facts.from)}",
          "to=#{engine(facts.to)}",
          "readback=#{engine(facts.readback)}",
          "since=#{iso(facts.since)}",
          "trigger=#{facts.turn_seq}",
          "class=#{@class}",
          "evidence=#{facts.evidence}",
          "failed-turn=#{facts.disposition}"
        ],
        " "
      )
  end

  defp lifecycle_detail(%{outcome: :applied} = facts, notices) do
    %{
      "session" => facts.session_key,
      "from" => engine(facts.from),
      "to" => engine(facts.to),
      "readback" => engine(facts.readback),
      "since" => iso(facts.since),
      "trigger" => facts.trigger_ref,
      "class" => @class,
      "evidence" => facts.evidence,
      "failedTurn" => Atom.to_string(facts.disposition),
      "assignments" => Enum.map(facts.assignments, & &1.id),
      "notices" => notices
    }
  end

  defp lifecycle_detail(%{outcome: :withheld} = facts, notices) do
    %{
      "session" => facts.session_key,
      "reason" => facts.reason,
      "engine" => engine(facts.from),
      "since" => iso(facts.since),
      "trigger" => facts.trigger_ref,
      "class" => @class,
      "episode" => facts.episode,
      "announced" => facts.announce,
      "assignments" => Enum.map(facts.assignments, & &1.id),
      "notices" => notices
    }
  end

  @doc "An engine tuple as `<harness>/<model>/<effort>`."
  @spec engine(%{harness: String.t(), model: Model.t() | nil}) :: String.t()
  def engine(%{harness: harness, model: %Model{} = model}),
    do: "#{harness}/#{model_name(model)}/#{model.effort || "none"}"

  def engine(%{harness: harness, model: nil}), do: "#{harness}/unknown/none"

  defp model_name(%Model{family: family, context: nil}), do: family
  defp model_name(%Model{family: family, context: context}), do: "#{family}[#{context}]"

  defp iso(ms), do: ms |> DateTime.from_unix!(:millisecond) |> DateTime.to_iso8601()
end
