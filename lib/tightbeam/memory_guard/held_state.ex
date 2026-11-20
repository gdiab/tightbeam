defmodule Tightbeam.MemoryGuard.HeldState do
  @moduledoc """
  The held-state read (memory limits v1.1 R7; quota v3 R1's fields and R2's
  exclusions). Build 3755's line has no v3 R1 read, so this is that one read
  for this contract's reason class, `host_capacity`, and it lists every other
  standing admission reason beside it (R6a). It is derived from the guard's
  state and the existing fence and evaluation rows, never a new poll (v3 R4).

  Each reason carries its class, detail, harness, provider and model, the
  host, since when, and the release condition in plain words. No credential,
  private field, raw payload, process list, pid or command line (v3 R2).
  """

  alias Tightbeam.{DB, Harness, HarnessProcess, LimitFallback, MemoryGuard}

  @doc """
  The held state of `session`, or nil when nothing holds its next turn. A
  read that cannot be completed says the state is unknown, never "not held".
  """
  @spec read(DB.server(), map()) :: map() | nil
  def read(db, session) do
    if queued?(db, session.session_key) do
      reasons =
        MemoryGuard.hold_reasons(session.session_key, db)
        |> Enum.map(&Map.merge(&1, identity(session)))

      reasons = reasons ++ other_reasons(db, session)

      case reasons do
        [] ->
          nil

        [first | _] ->
          held = %{reasonClass: first.reasonClass, reasons: reasons}

          # FS9: an open stuck episode on the session's host is shown on its
          # read too, while the session is held by it.
          if Enum.any?(reasons, &(&1[:detail] == "guard_unavailable")),
            do: Map.put(held, :stuckEpisodes, MemoryGuard.Episodes.read(db, session.host)),
            else: held
      end
    end
  rescue
    error -> unknown(session, Exception.message(error))
  catch
    :exit, reason -> unknown(session, inspect(reason))
  end

  defp unknown(session, why) do
    reason =
      Map.merge(identity(session), %{
        reasonClass: "unknown",
        detail: "unknown",
        host: session.host,
        since: nil,
        condition: "unknown: the held state cannot be read (#{why})"
      })

    %{reasonClass: "unknown", reasons: [reason]}
  end

  @doc "The sender's result for a wake to a held recipient (R7)."
  @spec sender_result(map() | nil) :: String.t() | nil
  def sender_result(%{reasonClass: class}), do: "recipient held (#{class})"
  def sender_result(_held), do: nil

  defp queued?(db, session_key) do
    case DB.query(db, "SELECT 1 FROM turns WHERE sessionKey=?1 AND status='queued' LIMIT 1", [
           session_key
         ]) do
      {:ok, [[1]]} -> true
      {:ok, []} -> false
      {:error, error} -> raise "the queued turns cannot be read: #{inspect(error)}"
    end
  end

  defp identity(session) do
    %{
      harness: session.harness,
      provider: session.provider,
      model: session.model && session.model.family
    }
  end

  defp other_reasons(db, session) do
    key = {Harness.parse!(session.harness).id(), "shared", session.host}

    park =
      case DB.query(db, "SELECT requestedAt FROM harness_park_fences WHERE adapterKey=?1", [
             HarnessProcess.adapter_key_name(key)
           ]) do
        {:ok, [[requested_at]]} ->
          [
            Map.merge(identity(session), %{
              reasonClass: "provider_quota",
              detail: "quota_park",
              host: session.host,
              since: requested_at,
              condition: "starts when the #{session.harness} park on #{session.host} is released"
            })
          ]

        {:ok, []} ->
          []

        {:error, error} ->
          raise "the park fences cannot be read: #{inspect(error)}"
      end

    fallback =
      if LimitFallback.held?(db, session.session_key) do
        [
          Map.merge(identity(session), %{
            reasonClass: "blocked_other",
            detail: "limit_fallback",
            host: session.host,
            since: nil,
            condition: "starts when the usage-limit fallback evaluation of this session ends"
          })
        ]
      else
        []
      end

    park ++ fallback
  end
end
