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
  alias Tightbeam.MemoryGuard.{Cgroup, Probe, Records}

  @detail "guard_unavailable"

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

        cond do
          # A resident session needs no launch: its turns are never held (FS1).
          resident?(db, session, live, opts) ->
            release(db, session_key, session.host, "resident")
            :ok

          # `off` in force lets a session launch onto a live adapter proceed;
          # a new adapter still waits for the guard (FS1, R2a).
          live != nil and mode_in_force(db, session.host) == "off" ->
            release(db, session_key, session.host, "off")
            :ok

          # FS9: a root override of the host's guard episode admits held
          # launches without the guard; the risk stays shown until it answers.
          (episode = overridden_guard_episode(db, session.host)) != nil ->
            Tightbeam.MemoryGuard.Episodes.applied(db, episode["episodeId"])
            release(db, session_key, session.host, "root override #{episode["episodeId"]}")
            :ok

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
      episode["kind"] == "guard" and
        Tightbeam.MemoryGuard.Episodes.override(db, episode["episodeId"]) != nil
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

  @doc "The open `guard_unavailable` hold of a session: `%{host, since}` or nil."
  @spec open_hold(DB.server(), String.t()) :: map() | nil
  def open_hold(db, session_key) do
    case DB.query(
           db,
           """
           SELECT h.ts, json_extract(h.detail,'$.host') FROM lifecycle_events h
           WHERE h.kind='memory_guard_hold' AND h.subject=?1
             AND json_extract(h.detail,'$.detail')=?2
             AND NOT EXISTS (
               SELECT 1 FROM lifecycle_events r
               WHERE r.kind='memory_guard_release' AND r.subject=?1 AND r.id>h.id
                 AND json_extract(r.detail,'$.detail')=?2)
           ORDER BY h.id DESC LIMIT 1
           """,
           [session_key, @detail]
         ) do
      {:ok, [[since, host]]} -> %{since: since, host: host}
      _ -> nil
    end
  end

  @doc "Every session with an open `guard_unavailable` hold: `[{session_key, host}]`."
  @spec held_sessions(DB.server()) :: [{String.t(), String.t()}]
  def held_sessions(db) do
    case DB.query(
           db,
           """
           SELECT DISTINCT h.subject, json_extract(h.detail,'$.host') FROM lifecycle_events h
           WHERE h.kind='memory_guard_hold' AND json_extract(h.detail,'$.detail')=?1
             AND NOT EXISTS (
               SELECT 1 FROM lifecycle_events r
               WHERE r.kind='memory_guard_release' AND r.subject=h.subject AND r.id>h.id
                 AND json_extract(r.detail,'$.detail')=?1)
           """,
           [@detail]
         ) do
      {:ok, rows} -> Enum.map(rows, fn [key, host] -> {key, host} end)
      _ -> []
    end
  end

  @doc "The held-state reasons (R7) of an open `guard_unavailable` hold."
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
  end

  # One hold row per hold: the record is the hold's state (FS7).
  defp hold(db, session_key, host) do
    if is_nil(open_hold(db, session_key)) do
      EventLog.lifecycle(
        db,
        "memory_guard_hold",
        session_key,
        JSON.encode!(%{host: host, detail: @detail})
      )
    end
  end

  @doc "End an open `guard_unavailable` hold, recording why."
  @spec release(DB.server(), String.t(), String.t(), String.t()) :: :ok
  def release(db, session_key, host, because) do
    if open_hold(db, session_key) do
      EventLog.lifecycle(
        db,
        "memory_guard_release",
        session_key,
        JSON.encode!(%{host: host, detail: @detail, because: because})
      )
    end

    :ok
  end

  @doc """
  The mode in force on `host` from its latest mode record: a mode whose
  transition is recorded incomplete is not in force (FS3), so this returns
  nil for it.
  """
  @spec mode_in_force(DB.server(), String.t()) :: String.t() | nil
  def mode_in_force(db, host) do
    case DB.query(
           db,
           """
           SELECT json_extract(detail,'$.mode'), json_extract(detail,'$.transition')
           FROM lifecycle_events WHERE kind='memory_guard_mode' AND subject=?1
           ORDER BY id DESC LIMIT 1
           """,
           [host]
         ) do
      {:ok, [[mode, nil]]} -> mode
      _ -> nil
    end
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

    with :ok <- no_incomplete_transition(db, host),
         :ok <- if(local?, do: no_kernel_limits(root, fs, opts), else: :ok) do
      {:ok, _} =
        DB.transaction(db, fn txn ->
          EventLog.lifecycle_in_txn(
            txn,
            "memory_guard_mode",
            host,
            JSON.encode!(%{
              host: host,
              mode: "off",
              reason: "an admin turned memory limits off for this host",
              transition: nil,
              by: "settings"
            })
          )

          # The step's configuration and the record are one step (FS2, FS7).
          case Records.publish_config(base_dir, %{
                 mode: "off",
                 fs: nil,
                 harness: nil,
                 sessionLimit: nil,
                 oomRaise: 100
               }) do
            :ok ->
              :ok

            {:error, error} ->
              raise "the launch step's configuration could not be written: #{inspect(error)}"
          end
        end)

      for {session_key, ^host} <- held_sessions(db), do: nudge(session_key)
      :in_force
    end
  rescue
    error -> {:not_applied, Exception.message(error)}
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
    if File.dir?(Cgroup.dir(fs, harness)) do
      case Cgroup.units(%{fs: fs, harness: harness}) do
        {:ok, units} ->
          Enum.reduce_while([harness | units], :ok, fn cgroup, :ok ->
            if Cgroup.lifted?(fs, cgroup),
              do: {:cont, :ok},
              else:
                {:halt,
                 {:not_applied, "#{cgroup} still carries a memory limit, or cannot be read"}}
          end)

        {:error, error} ->
          {:not_applied, error}
      end
    else
      :ok
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
