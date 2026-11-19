defmodule Tightbeam.RateLimitReset do
  @moduledoc """
  The provider's declared reset of a usage limit, and the park release at it
  (quota v3 R9(a); quota companion v1.1 B1-B4).

  A quota error that names when the limit lifts schedules one durable
  internal wake at that instant, for any harness whose typed error carries
  one. When it fires, the shared key's park is released without a successful
  turn, a probe or a principal; the incident stays open until a later
  success resolves it.
  """

  alias Tightbeam.{DB, Harness, HarnessProcess, HostZone, ParkStranding, QuotaRelease, Wakes}
  alias Tightbeam.DB.Txn

  @consumer "rate_limit_reset"

  def schedule_in_txn(
        %Txn{} = txn,
        session,
        {status, %{observationId: observation_id}},
        reason,
        observed_at
      )
      when is_binary(observation_id) do
    key = adapter_key(to_string(session.harness), session.host)

    case from_error(reason, observed_at, HostZone.zone(session.host)) do
      reset_at when is_integer(reset_at) ->
        wake_id = "rate-limit-reset:" <> observation_id

        if Txn.q(txn, "SELECT 1 FROM wakes WHERE wakeId=?1", [wake_id]) == [] do
          Wakes.schedule_in_txn(txn, %{
            wake_id: wake_id,
            session_key: session.session_key,
            origin: "process:tightbeam",
            consumer: @consumer,
            prompt: observation_id,
            due_at: reset_at
          })
        end

      nil ->
        :ok
    end

    # B4: a limit met again after a release is a new quota observation of the
    # still-open incident. It reinstates admission's hold whether or not its
    # error names a reset; a duplicate of an observation already handled does
    # not.
    case status != :duplicate and open_incident(txn, observation_id) do
      [[incident_id, _harness, _host]] ->
        HarnessProcess.begin_quota_park_in_txn(txn, key, incident_id)
        # Quota v3 R11: a park begun anew after a release is a new episode
        # with its own six-hour stranding check.
        ParkStranding.repark_in_txn(txn, incident_id, session.session_key, observed_at)

      _ ->
        :ok
    end

    :ok
  end

  def schedule_in_txn(%Txn{}, _session, _result, _reason, _observed_at), do: :ok

  def release(db, %{wake_id: wake_id}) do
    DB.transaction(db, fn txn ->
      at = System.system_time(:millisecond)

      case Txn.q(
             txn,
             "SELECT prompt,dueAt FROM wakes WHERE wakeId=?1 AND consumer=?2 AND state='pending'",
             [wake_id, @consumer]
           ) do
        [[observation_id, due_at]] when due_at <= at ->
          Wakes.consume_internal_in_txn(txn, wake_id)
          release_incident_in_txn(txn, observation_id, due_at, at)

        [[_, _]] ->
          {:deferred, :before_reset}

        [] ->
          :already_consumed
      end
    end)
  end

  defp release_incident_in_txn(txn, observation_id, due_at, at) do
    case open_incident(txn, observation_id) do
      [[incident_id, harness, host]] ->
        later_resets =
          Txn.q(
            txn,
            """
            SELECT 1 FROM wakes w
            JOIN harness_health_observations o ON o.id=w.prompt
            WHERE w.consumer=?1 AND w.state='pending' AND w.dueAt>?2
              AND o.incidentId=?3 LIMIT 1
            """,
            [@consumer, at, incident_id]
          )

        key = adapter_key(harness, host)

        if later_resets == [] and HarnessProcess.parked_in_txn?(txn, key) do
          # Reset permits another attempt; it is not a successful provider
          # response and must not resolve health or authorize success
          # redelivery. It is one cause of the recorded release step (C1).
          QuotaRelease.release_in_txn(txn, incident_id, harness, host,
            cause: "declared_reset",
            detail: %{observationId: observation_id, resetAt: due_at},
            readmit: true
          )
        end

        :ok

      [] ->
        :ok
    end
  end

  defp open_incident(txn, observation_id) do
    Txn.q(
      txn,
      """
      SELECT i.id,i.harness,i.host FROM harness_health_observations o
      JOIN harness_health_incidents i ON i.id=o.incidentId
      WHERE o.id=?1 AND i.state='open' AND i.failureClass='rate-limit-dead'
      """,
      [observation_id]
    )
  end

  defp adapter_key(harness, host), do: {Harness.parse!(harness).id(), "shared", host}

  @months ~w(jan feb mar apr may jun jul aug sep oct nov dec)
  @reset ~r/\bresets\s+(?:(?<month>[A-Za-z]{3})\s+(?<day>\d{1,2})(?:,\s*|\s+at\s+))?(?<hour>\d{1,2})(?::(?<minute>\d{2}))?\s*(?<period>am|pm)\s*(?<zone>\([A-Za-z0-9_+\/-]+\)|UTC)(?![A-Za-z])/i

  @doc """
  The declared reset of a typed quota error, in Unix milliseconds, or nil when
  it is unknown (companion v1.1 §1). `zone` is the IANA zone of the host the
  harness ran on; only Codex writes its reset in that zone.
  """
  @spec from_error(term(), integer(), String.t() | nil) :: integer() | nil
  def from_error(reason, at, zone \\ nil)

  # Codex states the reset in its usageLimitExceeded message, in the local
  # time of the host running Codex, with no zone marker: "… try again at
  # 9:59 AM." (`%-I:%M %p`) or "… try again at Nov 18th, 2026 9:59 AM."
  # (`%b %-d<ordinal>, %Y %-I:%M %p`). Its ACP adapter carries that text as
  # `data.message` (additionalDetails, else the error's message).
  def from_error(
        %{"data" => %{"codexErrorInfo" => "usageLimitExceeded"} = data} = reason,
        at,
        zone
      )
      when is_integer(at) do
    if is_binary(zone) do
      [data["message"], data["additionalDetails"], reason["message"]]
      |> Enum.filter(&is_binary/1)
      |> Enum.find_value(&codex_reset(&1, DateTime.from_unix!(at, :millisecond), zone))
    end
  end

  def from_error(%{"data" => %{"errorKind" => "rate_limit"}, "message" => message}, at, _zone)
      when is_binary(message) and is_integer(at) do
    case Regex.named_captures(@reset, message) do
      nil -> nil
      fields -> reset_at(fields, DateTime.from_unix!(at, :millisecond))
    end
  end

  def from_error(_error, _at, _zone), do: nil

  @codex_reset ~r/\btry again at\s+(?:(?<month>[A-Za-z]{3})\s+(?<day>\d{1,2})(?:st|nd|rd|th),\s+(?<year>\d{4})\s+)?(?<hour>\d{1,2}):(?<minute>\d{2})\s+(?<period>AM|PM)(?![A-Za-z0-9])/i

  defp codex_reset(message, observed, zone) do
    with fields when is_map(fields) <- Regex.named_captures(@codex_reset, message),
         hour = String.to_integer(fields["hour"]),
         minute = String.to_integer(fields["minute"]),
         true <- hour in 1..12 and minute in 0..59,
         {:ok, local_observed} <- DateTime.shift_zone(observed, zone, Tz.TimeZoneDatabase),
         {:ok, date} <- codex_date(fields, DateTime.to_date(local_observed)) do
      hour = rem(hour, 12) + if(String.upcase(fields["period"]) == "PM", do: 12, else: 0)

      reset =
        case DateTime.new(date, Time.new!(hour, minute, 0), zone, Tz.TimeZoneDatabase) do
          {:ok, reset} -> reset
          # A repeated local hour: the later instant, so the park cannot lift
          # before the provider's stated time.
          {:ambiguous, _first, second} -> second
          # A nonexistent local time names no instant.
          _ -> nil
        end

      # A reset not after the observation is not a deadline (companion §1).
      if reset && DateTime.compare(reset, observed) == :gt,
        do: DateTime.to_unix(reset, :millisecond)
    else
      _ -> nil
    end
  end

  # A time alone is that time on the observation's local date.
  defp codex_date(%{"month" => ""}, local_date), do: {:ok, local_date}

  defp codex_date(%{"month" => month, "day" => day, "year" => year}, _local_date) do
    case Enum.find_index(@months, &(&1 == String.downcase(month))) do
      nil -> :error
      index -> Date.new(String.to_integer(year), index + 1, String.to_integer(day))
    end
  end

  defp reset_at(fields, observed) do
    hour = String.to_integer(fields["hour"])
    minute = if fields["minute"] == "", do: 0, else: String.to_integer(fields["minute"])
    zone = fields["zone"] |> String.trim_leading("(") |> String.trim_trailing(")")
    zone = if String.upcase(zone) == "UTC", do: "Etc/UTC", else: zone

    with true <- hour in 1..12 and minute in 0..59,
         {:ok, local_observed} <- DateTime.shift_zone(observed, zone, Tz.TimeZoneDatabase) do
      hour = rem(hour, 12) + if(String.downcase(fields["period"]) == "pm", do: 12, else: 0)
      time = Time.new!(hour, minute, 0)
      # Provider text has minute precision. An error received during that
      # minute must not turn an already-due reset into another day's hold.
      observed_minute = div(DateTime.to_unix(observed), 60) * 60

      fields
      |> dates(DateTime.to_date(local_observed))
      |> Enum.reduce_while(nil, fn date, nil ->
        case DateTime.new(date, time, zone, Tz.TimeZoneDatabase) do
          {:ok, reset} ->
            next_reset([reset], observed_minute)

          {:ambiguous, first, second} ->
            # During a repeated hour, use the next occurrence of the stated
            # clock time, including the second occurrence if the first passed.
            next_reset([first, second], observed_minute)

          {:gap, _before_gap, after_gap} ->
            # A future nonexistent local time does not identify a deadline.
            # Keep the hold rather than inventing a reset after the clock jump.
            if DateTime.to_unix(after_gap) >= observed_minute,
              do: {:halt, nil},
              else: {:cont, nil}

          {:error, _} ->
            {:halt, nil}
        end
      end)
    else
      _ -> nil
    end
  end

  defp next_reset(resets, observed_minute) do
    case Enum.find(resets, &(DateTime.to_unix(&1) >= observed_minute)) do
      nil -> {:cont, nil}
      reset -> {:halt, DateTime.to_unix(reset, :millisecond)}
    end
  end

  defp dates(%{"month" => ""}, date), do: [date, Date.add(date, 1)]

  defp dates(%{"month" => month, "day" => day}, date) do
    case Enum.find_index(@months, &(&1 == String.downcase(month))) do
      nil ->
        []

      index ->
        for year <- [date.year, date.year + 1],
            {:ok, reset} <- [Date.new(year, index + 1, String.to_integer(day))],
            do: reset
    end
  end
end
