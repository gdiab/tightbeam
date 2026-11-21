defmodule Tightbeam.MemoryGuard.Unguarded do
  @moduledoc """
  Admission while the memory guard is down (memory limits v1.13 §6.1 FS1).

  The guard is Tightbeam's own; when it is not running or does not answer,
  Tightbeam fails closed. A turn that needs a launch is held with
  `host_capacity` detail `guard_unavailable`, with no time-out admission. A
  turn of a resident session runs. The hold is released when the guard
  answers again (its start releases and nudges every held session), or, for a
  session launch onto a live adapter, once `off` is in force on the host.

  Everything here reads durable records only, because the guard's own state
  is gone: the hold is a `memory_guard_hold` row, its release a
  `memory_guard_release` row, and the mode in force the latest
  `memory_guard_mode` row.
  """

  alias Tightbeam.{DB, EventLog, Harness, Org}
  alias Tightbeam.DB.Txn
  alias Tightbeam.MemoryGuard.{Cgroup, Probe, Publish, State}

  @detail "guard_unavailable"
  # The open hold's kind in `memory_guard_open` (one per session).
  @open_kind "unguarded_hold"

  @doc "The detail this module holds with."
  def detail, do: @detail

  @doc """
  Admission for `session_key`'s next turn without the guard:
  `:ok` or `{:held, ["guard_unavailable"]}`.
  """
  @spec admit(DB.server(), String.t(), keyword()) :: :ok | {:held, [String.t()]}
  def admit(db, session_key, opts \\ []) do
    case Org.get(db, session_key) do
      nil ->
        :ok

      session ->
        key = {Harness.parse!(session.harness).id(), "shared", session.host}
        live = Keyword.get(opts, :live_adapter, &live_adapter/1).(key)

        # FS7: an admission is its release's durable step. A release whose
        # record cannot be written has not happened: the turn stays held, and
        # the next ask retries it.
        admitted = fn result -> if result == :ok, do: :ok, else: {:held, [@detail]} end

        cond do
          # A resident session needs no launch: its turns are never held (FS1).
          resident?(db, session, live, opts) ->
            admitted.(release(db, session_key, session.host, "resident"))

          # `off` in force lets a session launch onto a live adapter proceed;
          # a new adapter still waits for the guard (FS1, R2a).
          live != nil and mode_in_force(db, session.host) == "off" ->
            admitted.(release(db, session_key, session.host, "off"))

          # FS9: a root override of the host's guard episode admits held
          # launches without the guard; the risk stays shown until it answers.
          # The admission (the hold's release) and `override_applied` are one
          # transaction: neither is recorded without the other (FS9 B4, FS7).
          (episode = overridden_guard_episode(db, session.host)) != nil ->
            id = episode["episodeId"]

            admitted.(
              release(db, session_key, session.host, "root override #{id}",
                then: &Tightbeam.MemoryGuard.Episodes.applied_in_txn(&1, id)
              )
            )

          true ->
            hold(db, session_key, session.host)
            {:held, [@detail]}
        end
    end
  rescue
    # The records cannot be read either: still held, never admitted unguarded.
    _ -> {:held, [@detail]}
  end

  defp resident?(_db, _session, nil, _opts), do: false

  defp resident?(db, session, adapter, opts) do
    harness = Harness.parse!(session.harness)

    if Harness.session_processes?(harness) do
      case Org.current_pointer(db, session.session_key) do
        %{harness_session_id: sid} when is_binary(sid) ->
          Keyword.get(opts, :resident?, &Tightbeam.Acp.Adapter.resident?/2).(adapter, sid)

        _ ->
          false
      end
    else
      true
    end
  rescue
    _ -> false
  end

  defp overridden_guard_episode(db, host) do
    Enum.find(Tightbeam.MemoryGuard.Episodes.active(db, host), fn episode ->
      episode["kind"] == "guard" and episode["override"] != nil
    end)
  end

  # The live adapter for a key, without starting one.
  defp live_adapter(key) do
    if Tightbeam.AdapterCoordinator.ready?(key) do
      case Tightbeam.AdapterCoordinator.adapter_for(key) do
        {:ok, pid, _generation} when is_pid(pid) -> pid
        {:ok, pid} when is_pid(pid) -> pid
        _ -> nil
      end
    end
  catch
    :exit, _ -> nil
  end

  @doc """
  The open `guard_unavailable` hold of a session: `%{host, since}` or nil.
  Raises when it cannot be read: an unread hold is not an absent one.
  """
  @spec open_hold(DB.server(), String.t()) :: map() | nil
  def open_hold(db, session_key) do
    case DB.transaction(db, &open_hold_in_txn(&1, session_key)) do
      {:ok, hold} ->
        hold

      {:error, error} ->
        raise "the guard_unavailable hold cannot be read: #{Exception.message(error)}"
    end
  end

  defp open_hold_in_txn(txn, session_key) do
    case Txn.q(
           txn,
           "SELECT host, openedAt FROM memory_guard_open WHERE kind=?1 AND ref=?2",
           [@open_kind, session_key]
         ) do
      [[host, since]] -> %{since: since, host: host}
      [] -> nil
    end
  end

  @nudge_page 64

  @doc """
  When launches on `host` have been held `guard_unavailable` since: the
  oldest open hold's start (one indexed row, re-review att_5f6e6736 B4), or
  nil when none is open. `{:error, message}` when it cannot be read.
  """
  @spec held_since(DB.server(), String.t()) :: {:ok, integer() | nil} | {:error, String.t()}
  def held_since(db, host) do
    with {:ok, oldest} <- State.oldest(db, @open_kind, host),
         do: {:ok, oldest && oldest.opened_at}
  end

  @doc """
  Nudge one page (64) of the sessions held `guard_unavailable` on `host`,
  oldest first after `cursor` (nil: from the start). Returns the cursor of
  the next page, or nil when this was the last. A nudge is idempotent: a
  lane nudged needlessly asks again and is held again.
  """
  @spec nudge_held(DB.server(), String.t(), tuple() | nil) ::
          {:ok, tuple() | nil} | {:error, String.t()}
  def nudge_held(db, host, cursor) do
    with {:ok, page} <- State.page(db, @open_kind, host, cursor, nil, @nudge_page) do
      for %{subject: session_key} <- page, do: nudge(session_key)

      {:ok,
       if(length(page) == @nudge_page,
         do: {List.last(page).opened_at, List.last(page).ref}
       )}
    end
  end

  @doc """
  The held-state reasons (R7) of an open `guard_unavailable` hold. A hold that
  cannot be read is shown as a reason whose state is unknown, never as none.
  """
  @spec hold_reasons(DB.server(), String.t()) :: [map()]
  def hold_reasons(db, session_key) do
    case open_hold(db, session_key) do
      nil ->
        []

      %{since: since, host: host} ->
        [
          %{
            reasonClass: "host_capacity",
            detail: @detail,
            host: host,
            since: since,
            condition:
              "starts when Tightbeam's memory guard on #{host} is running again " <>
                "(an admin can also set the host's memory limits off)"
          }
        ]
    end
  rescue
    error ->
      [
        %{
          reasonClass: "host_capacity",
          detail: @detail,
          condition: "unknown: #{Exception.message(error)}"
        }
      ]
  end

  # One hold per session at a time: its open row and its record are one
  # transaction (FS7).
  defp hold(db, session_key, host) do
    {:ok, _} =
      DB.transaction(db, fn txn ->
        if is_nil(open_hold_in_txn(txn, session_key)) do
          State.open_in_txn(txn, @open_kind, session_key, session_key, host, nil)

          EventLog.lifecycle_in_txn(
            txn,
            "memory_guard_hold",
            session_key,
            JSON.encode!(%{host: host, detail: @detail})
          )
        end
      end)
  end

  @doc """
  End an open `guard_unavailable` hold, recording why. `:ok`, or
  `{:error, message}` when the release could not be recorded (the hold stands
  and the release is retried).
  """
  @spec release(DB.server(), String.t(), String.t(), String.t(), keyword()) ::
          :ok | {:error, String.t()}
  def release(db, session_key, host, because, opts \\ []) do
    DB.transaction(db, fn txn ->
      if open_hold_in_txn(txn, session_key) do
        State.close_in_txn(txn, @open_kind, session_key)

        EventLog.lifecycle_in_txn(
          txn,
          "memory_guard_release",
          session_key,
          JSON.encode!(%{host: host, detail: @detail, because: because})
        )
      end

      # A record of the release's own effect, in the same step.
      Keyword.get(opts, :then, fn _txn -> :ok end).(txn)
    end)
    |> case do
      {:ok, _} -> :ok
      {:error, error} -> {:error, Exception.message(error)}
    end
  catch
    :exit, reason -> {:error, inspect(reason)}
  end

  @doc """
  The mode in force on `host` from its latest mode record: a mode whose
  transition is recorded incomplete is not in force (FS3), so this returns
  nil for it.
  """
  @spec mode_in_force(DB.server(), String.t()) :: String.t() | nil
  def mode_in_force(db, host) do
    # D3: a mode whose step configuration is not yet published is requested,
    # not applied.
    case DB.transaction(db, fn txn ->
           case Txn.q(
                  txn,
                  """
                  SELECT json_extract(detail,'$.mode'), json_extract(detail,'$.transition'),
                         json_extract(detail,'$.publish')
                  FROM lifecycle_events WHERE kind='memory_guard_mode' AND subject=?1
                  ORDER BY id DESC LIMIT 1
                  """,
                  [host]
                ) do
             [[mode, nil, publish]] -> if Publish.done_in_txn?(txn, publish), do: mode
             _ -> nil
           end
         end) do
      {:ok, mode} -> mode
      _ -> nil
    end
  catch
    :exit, _ -> nil
  end

  @doc """
  FS1 / F8: a requested `off` comes into force without the guard only on
  positive evidence that no kernel limit of this contract exists: no budget
  group, or one whose every unit is at `memory.max` `max`, `memory.swap.max`
  `max` and `memory.oom.group` 0, and no transition recorded incomplete. Then
  the change is recorded and the step's `off` configuration published in one
  step. Returns `:in_force` or `{:not_applied, reason}`.
  """
  @spec bring_off_into_force(DB.server(), String.t(), String.t(), keyword()) ::
          :in_force | {:not_applied, String.t()}
  def bring_off_into_force(db, host, base_dir, opts \\ []) do
    root = Keyword.get(opts, :root, "/")
    fs = Keyword.get(opts, :cgroup_fs, Path.join(root, "sys/fs/cgroup"))

    # A remote host is `count-only` (R12, NG4): no kernel limit of this
    # contract can exist there, so only the mode record is evidence.
    local? = Keyword.get(opts, :local?, true)

    bytes =
      Publish.config_bytes(%{
        mode: "off",
        fs: nil,
        harness: nil,
        sessionLimit: nil,
        oomRaise: 100
      })

    now = System.system_time(:millisecond)

    # D3: the record and its publication intent commit first; the file is
    # written after, and `off` is in force only once it is.
    with :ok <- no_incomplete_transition(db, host),
         :ok <- if(local?, do: no_kernel_limits(root, fs, opts), else: :ok),
         {:ok, publish} <-
           recorded(
             DB.transaction(db, fn txn ->
               publish = if local?, do: Publish.config_in_txn(txn, host, bytes, now)

               EventLog.lifecycle_in_txn(
                 txn,
                 "memory_guard_mode",
                 host,
                 JSON.encode!(%{
                   host: host,
                   mode: "off",
                   reason: "an admin turned memory limits off for this host",
                   transition: nil,
                   by: "settings",
                   publish: publish
                 })
               )

               publish
             end)
           ),
         :ok <- published(db, base_dir, publish, bytes, now) do
      # The change is in force: the first page of held lanes is nudged now;
      # the Watcher nudges the rest, a page per pass, while the guard is down
      # (and the guard's own pass over the holds once it is back).
      _ = nudge_held(db, host, nil)

      :in_force
    end
  rescue
    error -> {:not_applied, Exception.message(error)}
  end

  defp recorded({:ok, publish}), do: {:ok, publish}

  defp recorded({:error, error}),
    do: {:not_applied, "the change could not be recorded: #{Exception.message(error)}"}

  # Nothing to publish for a remote host; otherwise `off` is in force only
  # once its configuration is written. One that is not yet written stays a
  # pending publication, which the Watcher retries.
  defp published(_db, _base_dir, nil, _bytes, _now), do: :ok

  defp published(db, base_dir, publish, bytes, now) do
    case Publish.config(db, base_dir, publish, bytes, now) do
      :ok ->
        :ok

      {:error, error} ->
        {:not_applied,
         "recorded; the launch step's settings are not yet written (#{error}); retried"}
    end
  end

  defp no_incomplete_transition(db, host) do
    case DB.query(
           db,
           """
           SELECT json_extract(detail,'$.transition') FROM lifecycle_events
           WHERE kind='memory_guard_mode' AND subject=?1 ORDER BY id DESC LIMIT 1
           """,
           [host]
         ) do
      {:ok, [[transition]]} when is_binary(transition) ->
        {:not_applied, "a change of memory limits mode is still incomplete: " <> transition}

      {:ok, _} ->
        :ok

      {:error, error} ->
        {:not_applied, "the mode record cannot be read: #{inspect(error)}"}
    end
  end

  defp no_kernel_limits(root, fs, opts) do
    case Keyword.get(opts, :harness_candidates, fn -> Probe.harness_candidates(root) end).() do
      {:ok, candidates} ->
        Enum.reduce_while(candidates, :ok, fn harness, :ok ->
          case lifted?(fs, harness) do
            :ok -> {:cont, :ok}
            {:not_applied, _} = no -> {:halt, no}
          end
        end)

      :error ->
        {:not_applied,
         "the gateway's own cgroup cannot be read, so no evidence that no limit is in force"}
    end
  end

  # No budget group at all, or every cgroup in it lifted.
  defp lifted?(fs, harness) do
    case Cgroup.exists?(Cgroup.dir(fs, harness)) do
      false ->
        :ok

      :unknown ->
        {:not_applied, "#{harness} cannot be looked at, so no evidence that it carries no limit"}

      true ->
        lifted_units(fs, harness)
    end
  end

  defp lifted_units(fs, harness) do
    case Cgroup.units(%{fs: fs, harness: harness}) do
      {:ok, units} ->
        Enum.reduce_while([harness | units], :ok, fn cgroup, :ok ->
          if Cgroup.lifted?(fs, cgroup),
            do: {:cont, :ok},
            else:
              {:halt, {:not_applied, "#{cgroup} still carries a memory limit, or cannot be read"}}
        end)

      {:error, error} ->
        {:not_applied, error}
    end
  end

  defp nudge(session_key) do
    case Process.whereis(Tightbeam.LaneManager) do
      nil -> :ok
      _ -> Tightbeam.LaneManager.ensure_lane(session_key)
    end
  catch
    :exit, _ -> :ok
  end
end
