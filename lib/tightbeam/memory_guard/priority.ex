defmodule Tightbeam.MemoryGuard.Priority do
  @moduledoc """
  Who goes first for a launch slot (memory limits v1.4 §1, R3a, R3b), from
  data only the gateway writes:

  - **Main**: the session whose `kind` is `main`. A key prefix is not Main.
  - **User-facing**: Main, or a session with a user-originated turn or wake
    pending: a queued turn or pending prompt wake whose gateway-recorded
    `origin` is `user:<id>`, or a queued notice-batch carrier that carries
    such a post. Nothing a session sets about itself counts (AS5).
  - **Worker**: every other session.
  - **Reserved Main**: the Main of the gateway's founding user, the earliest
    created user. The founder is recorded once (`memory_guard_founder`); if
    that user is later gone there is no reserved Main, and the slot never
    passes to another user (AS6).
  """

  alias Tightbeam.{DB, EventLog, NoticeBatcher, Org}
  alias Tightbeam.DB.Txn

  @classes %{"main" => 0, "user-facing" => 1, "worker" => 2}

  @doc "The class rank: lower goes first."
  def rank(class), do: Map.fetch!(@classes, class)

  @doc "`main`, `user-facing` or `worker`."
  @spec class(DB.server(), map()) :: String.t()
  def class(_db, %{kind: "main"}), do: "main"

  def class(db, %{session_key: key}) do
    if user_originated_pending?(db, key), do: "user-facing", else: "worker"
  end

  @doc "Whether `session_key` has a user-originated turn or wake pending."
  @spec user_originated_pending?(DB.server(), String.t()) :: boolean()
  def user_originated_pending?(db, session_key) do
    {:ok, pending?} =
      DB.transaction(db, fn txn ->
        Txn.q(
          txn,
          """
          SELECT 1 FROM turns WHERE sessionKey=?1 AND status='queued' AND origin LIKE 'user:%'
          UNION ALL
          SELECT 1 FROM wakes WHERE sessionKey=?1 AND state='pending' AND consumer='prompt'
            AND origin LIKE 'user:%'
          LIMIT 1
          """,
          [session_key]
        ) != [] or carrier_with_user_post?(txn, session_key)
      end)

    pending?
  end

  defp carrier_with_user_post?(txn, session_key) do
    txn
    |> Txn.q(
      "SELECT wakeId FROM turns WHERE sessionKey=?1 AND status='queued' AND isBatchCarrier=1 AND wakeId IS NOT NULL",
      [session_key]
    )
    |> Enum.any?(fn [wake_id] -> NoticeBatcher.carrier_human_posts_in_txn(txn, wake_id) != [] end)
  end

  @doc """
  The reserved Main's session key, or nil when there is no reserved Main
  (no founding user yet, the founder is gone, or the founder has no Main).
  """
  @spec reserved_main(DB.server()) :: %{user: String.t(), session_key: String.t() | nil} | nil
  def reserved_main(db) do
    case founder(db) do
      nil ->
        nil

      user ->
        # L5: an unreadable user is not a removed one; the decision that needs
        # it is held instead (v1.13 FS1), and the slot is never lent on a guess.
        exists? =
          case DB.query(db, "SELECT 1 FROM users WHERE userId=?1", [user]) do
            {:ok, [[1]]} -> true
            {:ok, []} -> false
            {:error, error} -> raise "the founding user cannot be read: #{inspect(error)}"
          end

        key = Org.personal_session_key(user)

        cond do
          not exists? -> %{user: user, session_key: nil, gone: true}
          match?(%{kind: "main"}, Org.get(db, key)) -> %{user: user, session_key: key}
          true -> %{user: user, session_key: nil}
        end
    end
  end

  # The founding user, recorded the first time a user exists; never re-derived.
  defp founder(db) do
    case DB.query(
           db,
           "SELECT subject FROM lifecycle_events WHERE kind='memory_guard_founder' ORDER BY id LIMIT 1"
         ) do
      {:ok, [[user]]} ->
        user

      {:ok, []} ->
        case DB.query(db, "SELECT userId FROM users ORDER BY createdAt, userId LIMIT 1") do
          {:ok, [[user]]} ->
            EventLog.lifecycle(db, "memory_guard_founder", user, JSON.encode!(%{user: user}))
            user

          {:ok, []} ->
            nil

          {:error, error} ->
            raise "the users cannot be read: #{inspect(error)}"
        end
    end
  end
end
