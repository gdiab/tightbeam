defmodule Tightbeam.ParkStranding do
  @moduledoc """
  The six-hour stranding notice for a rate-limit park (quota-stranding
  contract v3, R11; I-notices (ii)).

  When a `rate-limit-dead` incident opens and parks its shared adapter key,
  `schedule_in_txn/3` persists ONE internal wake, `park-stranding:<incidentId>`,
  due six hours after the incident opened. Its id makes it once per park
  episode (a re-park of the same incident finds it) and its row makes it
  survive a gateway restart.

  When it comes due, `notify/3` consumes it and, in the same transaction,
  checks that the incident is still open, that the park still stands on the
  key, and that no reset time is known for the incident (no pending
  `rate_limit_reset` wake for one of its observations). If any check fails it records why
  and sends nothing. Otherwise it schedules one blocker-class notice to each
  delivery owner of the held work and to the Main of each affected owner, and
  records that it did. It takes no other action: nothing is killed, retried,
  resumed, released, reassigned or staffed.
  """

  alias Tightbeam.{DB, EventLog, Harness, HarnessHealth, HarnessProcess, Org, Wakes}
  alias Tightbeam.DB.Txn

  @consumer "park_stranding"
  @wake_prefix "park-stranding:"
  @notice_prefix "park-stranding-notice:"
  @process "process:tightbeam"
  @class "rate-limit-dead"
  @after_ms 6 * 60 * 60 * 1000

  @doc "The wait, from the incident's opening, before the notice is due."
  @spec after_ms() :: pos_integer()
  def after_ms, do: @after_ms

  @doc "The deterministic id of an incident's stranding wake."
  @spec wake_id(String.t()) :: String.t()
  def wake_id(incident_id) when is_binary(incident_id), do: @wake_prefix <> incident_id

  @doc """
  Persist the incident's stranding wake inside the transaction that opened the
  incident and began its park. A second call for the same incident is a no-op.
  """
  @spec schedule_in_txn(Txn.t(), String.t(), map()) :: :ok
  def schedule_in_txn(%Txn{} = txn, incident_id, %{observed_at: opened_at} = input)
      when is_binary(incident_id) and is_integer(opened_at) do
    wake_id = wake_id(incident_id)

    if Txn.q(txn, "SELECT 1 FROM wakes WHERE wakeId=?1", [wake_id]) == [] do
      case anchor_session(txn, incident_id, Map.get(input, :session_key)) do
        nil ->
          # No session of this harness exists on this host and the evidence
          # names none: nothing is held and no owner is affected.
          skipped_in_txn(txn, incident_id, "no_affected_session", %{
            harness: input.harness,
            host: input.host,
            openedAt: opened_at
          })

        session_key ->
          Wakes.schedule_in_txn(txn, %{
            wake_id: wake_id,
            session_key: session_key,
            origin: @process,
            consumer: @consumer,
            prompt: incident_id,
            due_at: opened_at + @after_ms,
            # The anchor session is only where the row is filed. Ungated, its
            # retirement neither cancels nor re-mints this one-shot wake.
            target_gate: 0
          })
      end
    end

    :ok
  end

  @doc """
  The internal consumer. `at` is the decision time; the scheduler passes none
  and the current time is used.
  """
  @spec notify(DB.server(), %{wake_id: String.t()}, integer()) :: {:ok, term()} | {:error, term()}
  def notify(db, %{wake_id: wake_id}, at \\ System.system_time(:millisecond))
      when is_binary(wake_id) and is_integer(at) do
    DB.transaction(db, fn txn ->
      case Txn.q(
             txn,
             "SELECT prompt,dueAt FROM wakes WHERE wakeId=?1 AND consumer=?2 AND state='pending'",
             [wake_id, @consumer]
           ) do
        [[incident_id, due_at]] when due_at <= at ->
          Wakes.consume_internal_in_txn(txn, wake_id)
          decide_in_txn(txn, incident_id, wake_id, at)

        [[_, _]] ->
          {:deferred, :before_deadline}

        [] ->
          :already_consumed
      end
    end)
  end

  defp decide_in_txn(txn, incident_id, wake_id, at) do
    case Txn.q(
           txn,
           "SELECT harness,host,state,openedAt FROM harness_health_incidents WHERE id=?1 AND failureClass=?2",
           [incident_id, @class]
         ) do
      [[harness, host, state, opened_at]] ->
        facts = %{
          incident_id: incident_id,
          wake_id: wake_id,
          harness: harness,
          host: host,
          opened_at: opened_at,
          at: at
        }

        cond do
          state != "open" ->
            skipped_in_txn(txn, incident_id, "incident_" <> state, detail(facts))

          not HarnessProcess.parked_in_txn?(txn, adapter_key(harness, host)) ->
            skipped_in_txn(txn, incident_id, "park_released", detail(facts))

          reset_known?(txn, incident_id) ->
            skipped_in_txn(txn, incident_id, "reset_known", detail(facts))

          true ->
            send_in_txn(txn, facts)
        end

      [] ->
        # Incidents are never deleted, and this wake is written with its
        # incident. A missing row is not a released park: refuse by name.
        raise "park stranding wake #{wake_id} names no #{@class} incident #{incident_id}"
    end
  end

  defp send_in_txn(txn, facts) do
    held = held_sessions(txn, facts.harness, facts.host)
    assignments = held_assignments(txn, held)
    recipients = recipients(txn, facts.incident_id, held, assignments)

    case recipients do
      [] ->
        skipped_in_txn(txn, facts.incident_id, "no_active_recipient", detail(facts))

      recipients ->
        text = notice_text(facts, held, assignments)

        notices =
          Enum.map(recipients, fn recipient ->
            notice_wake_id = notice_wake_id(facts.incident_id, recipient)

            # The consumed stranding wake already makes this once; the
            # per-recipient id keeps a replayed transaction from doubling it.
            if Txn.q(txn, "SELECT 1 FROM wakes WHERE wakeId=?1", [notice_wake_id]) == [] do
              wake =
                Wakes.schedule_in_txn(txn, %{
                  wake_id: notice_wake_id,
                  session_key: recipient,
                  origin: @process,
                  prompt: text,
                  due_at: facts.at,
                  class: "blocker"
                })

              Wakes.publish_change_in_txn(txn, "wake.scheduled", wake.wake_id)
            end

            %{recipient: recipient, wakeId: notice_wake_id}
          end)

        EventLog.lifecycle_in_txn(
          txn,
          "rate_limit_park_stranding_notified",
          facts.incident_id,
          facts
          |> detail()
          |> Map.merge(%{
            notices: notices,
            heldSessions: Enum.map(held, & &1.session_key),
            heldAssignments: Enum.map(assignments, & &1.id)
          })
          |> JSON.encode!()
        )

        {:notified, Enum.map(notices, & &1.wakeId)}
    end
  end

  # The population a release re-admits (`RateLimitReset`): active sessions of
  # this harness on this host with queued turns.
  defp held_sessions(txn, harness, host) do
    Txn.q(
      txn,
      """
      SELECT DISTINCT s.sessionKey,s.displayName,s.ownerUserId FROM sessions s
      JOIN turns t ON t.sessionKey=s.sessionKey
      WHERE s.harness=?1 AND s.host=?2 AND s.state='active' AND t.status='queued'
      ORDER BY s.sessionKey
      """,
      [harness, host]
    )
    |> Enum.map(fn [key, name, owner] ->
      %{session_key: key, display_name: name, owner_user_id: owner}
    end)
  end

  defp held_assignments(txn, held) do
    Enum.flat_map(held, fn session ->
      Txn.q(
        txn,
        "SELECT id FROM assignments WHERE holderKey=?1 AND state='open' ORDER BY id",
        [session.session_key]
      )
      |> Enum.map(fn [id] -> %{id: id, holder: session} end)
    end)
  end

  # Each held assignment's delivery owner, by the terminal-notice rule; then
  # the Main of each held session's owner. With no held session, the Main of
  # each owner of the incident's affected sessions. Deduped, active only.
  defp recipients(txn, incident_id, held, assignments) do
    owners =
      for assignment <- assignments do
        case Wakes.delivery_owner_in_txn(txn, assignment.id) do
          {:ok, recipient} -> recipient
          {:error, _} -> Org.personal_session_key(assignment.holder.owner_user_id)
        end
      end

    mains =
      case held do
        [] -> affected_owners(txn, incident_id)
        held -> Enum.map(held, & &1.owner_user_id)
      end
      |> Enum.map(&Org.personal_session_key/1)

    (owners ++ mains)
    |> Enum.uniq()
    |> Enum.filter(fn key ->
      Txn.q(txn, "SELECT 1 FROM sessions WHERE sessionKey=?1 AND state='active'", [key]) ==
        [[1]]
    end)
  end

  # The sessions the incident recorded as affected when it opened, and any its
  # evidence later named (`harness_health_members`).
  defp affected_owners(txn, incident_id) do
    Txn.q(
      txn,
      """
      SELECT DISTINCT s.ownerUserId FROM harness_health_members m
      JOIN sessions s ON s.sessionKey=m.sessionKey
      WHERE m.incidentId=?1 ORDER BY s.ownerUserId
      """,
      [incident_id]
    )
    |> Enum.map(&hd/1)
  end

  defp anchor_session(_txn, _incident_id, session_key) when is_binary(session_key),
    do: session_key

  defp anchor_session(txn, incident_id, nil) do
    case Txn.q(
           txn,
           "SELECT sessionKey FROM harness_health_members WHERE incidentId=?1 ORDER BY sessionKey LIMIT 1",
           [incident_id]
         ) do
      [[session_key]] -> session_key
      [] -> nil
    end
  end

  # A reset is known while a declared reset for one of the incident's
  # observations is still pending: that wake will release the park. A fired
  # one already had its chance and a canceled one never will.
  defp reset_known?(txn, incident_id) do
    Txn.q(
      txn,
      """
      SELECT 1 FROM wakes w
      JOIN harness_health_observations o ON o.id=w.prompt
      WHERE w.consumer='rate_limit_reset' AND w.state='pending' AND o.incidentId=?1 LIMIT 1
      """,
      [incident_id]
    ) != []
  end

  defp skipped_in_txn(txn, incident_id, reason, detail) do
    EventLog.lifecycle_in_txn(
      txn,
      "rate_limit_park_stranding_skipped",
      incident_id,
      detail |> Map.put(:reason, reason) |> JSON.encode!()
    )

    {:skipped, reason}
  end

  defp detail(facts) do
    %{
      incidentId: facts.incident_id,
      wakeId: facts.wake_id,
      harness: facts.harness,
      host: facts.host,
      openedAt: facts.opened_at,
      checkedAt: facts.at,
      principal: @process,
      cause: "no release within 6 hours and no known reset"
    }
  end

  defp notice_wake_id(incident_id, recipient) do
    digest =
      :crypto.hash(:sha256, recipient)
      |> Base.encode16(case: :lower)
      |> binary_part(0, 32)

    @notice_prefix <> incident_id <> ":" <> digest
  end

  @doc false
  @spec notice_text(map(), [map()], [map()]) :: String.t()
  def notice_text(facts, held, assignments) do
    """
    [rate-limit park unreleased after 6 hours]

    The #{facts.harness} harness on #{facts.host} has been parked by rate-limit incident #{facts.incident_id} since #{iso(facts.opened_at)}. No reset time is known for it, and nothing released it within 6 hours: no declared reset, no later successful turn, no explicit resume.

    #{held_lines(held)}

    #{assignment_lines(assignments)}

    #{HarnessHealth.repair_message(@class)}

    This is a single notice from #{@process}, sent once for this park. Nothing else was done: no turn was started, retried or cancelled, the park was not released, and no assignment was changed or transferred.
    """
    |> String.trim_trailing()
  end

  defp held_lines([]), do: "No session of this harness on this host has queued work waiting."

  defp held_lines(held) do
    Enum.map_join(held, "\n", fn session ->
      "- #{session.display_name} (#{session.session_key})"
    end)
    |> then(&("Sessions with queued work held by the park:\n" <> &1))
  end

  defp assignment_lines([]), do: "No open assignment is held by those sessions."

  defp assignment_lines(assignments) do
    Enum.map_join(assignments, "\n", fn assignment ->
      "- #{assignment.id}, held by #{assignment.holder.display_name} (#{assignment.holder.session_key})"
    end)
    |> then(&("Open assignments held:\n" <> &1))
  end

  defp iso(ms), do: ms |> DateTime.from_unix!(:millisecond) |> DateTime.to_iso8601()

  defp adapter_key(harness, host), do: {Harness.parse!(harness).id(), "shared", host}
end
