defmodule Tightbeam.MemoryGuard do
  @moduledoc """
  Memory limits on the harness processes Tightbeam launches (contract
  harness-memory-limits v1.1, G2/G3). One server per gateway. It keeps, per
  host, the mode (R12), the effective settings (R17), host available and the
  Tightbeam total, and decides every launch on that host in one serialized
  step (R3).

  What it does:

  - **Admission (R3, R5, R2 approach, R6, R6a).** A lane asks `admit/1`
    before it claims a queued turn. A turn that needs no launch (its session
    process is resident) is admitted. A turn that needs one is held, `queued`
    and unclaimed, while the floor or the budget approach holds the host, or
    the resident cap is reached and no idle session process can be closed.
    Held turns are admitted oldest first.
  - **Idle close (R4).** The least recently used idle session process is
    closed through the harness's own `session/close`, which clears residency;
    its next turn loads the saved conversation.
  - **Limits (R1, R2).** `watched`: the gateway samples tree memory every
    second and ends a tree over its limit through the existing tree kill,
    recording the intent first (R10a). `enforced`: the kernel does, in the
    layout of R12c; the gateway reads the unit's local OOM counters (R10).
  - **Adapter end (R2a).** Every session tree of an ended adapter is ended
    before a replacement adapter for its key is launched.
  - **Attribution (R8, R9, R15).** `memory_kill/1` tells the turn runner, from
    the guard's own records only, whether a session or adapter tree was ended by
    a memory kill. It reads ETS, so it is safe inside a transaction.

  Nothing here changes a host setting (M-V5); every lifecycle record is a
  `lifecycle_events` row.
  """

  use GenServer
  require Logger

  alias Tightbeam.{DB, EventLog, Harness, HarnessProcess, Org, Placement}
  alias Tightbeam.MemoryGuard.{Admission, Cgroup, Priority, Probe, ProcTree, Records, Settings}

  @table :tightbeam_memory_guard
  @details ~w(resident_cap memory_floor memory_budget)
  @kill_retention_ms 15 * 60_000
  @gib 1024 * 1024 * 1024

  ## Public, ETS-backed reads (safe in any process and inside a transaction)

  @doc "The host-capacity details (R7) this contract defines."
  def details, do: @details

  @doc "Whether the guard is running."
  def running?, do: is_pid(Process.whereis(__MODULE__))

  @doc """
  The guard's last published view of a host: mode, reason, effective
  settings, host available, Tightbeam total, resident count, holds.
  """
  @spec host_view(String.t()) :: map() | nil
  def host_view(host) do
    case lookup({:host, host}) do
      [{_, view}] -> view
      _ -> nil
    end
  end

  @doc """
  The host-level memory reasons standing on `host` now (`memory_floor`,
  `memory_budget`), for a release of another reason to see what remains
  (R6a). Empty when the guard is not running.
  """
  @spec host_reasons(String.t()) :: [String.t()]
  def host_reasons(host) do
    case host_view(host) do
      %{holds: holds} -> holds
      _ -> []
    end
  end

  @doc """
  Whether the tree a turn ran on was ended by a memory kill (R10), from the
  guard's own records: `%{limit: "session" | "budget", scope: "session" |
  "adapter", bytes: n | nil, limit_bytes: n | nil, mode: m}` or nil.

  `match` carries `:host`, `:harness_session_id` (the session's process) and
  `:adapter_key` (its adapter), and `:since` (ms): only a kill at or after the
  turn's claim counts. In `enforced` mode the unit's counters are read now
  when no record exists yet (AS1).
  """
  @spec memory_kill(map()) :: map() | nil
  def memory_kill(%{host: host} = match) do
    since = Map.get(match, :since, 0)

    recorded =
      for {{:kill, _id}, kill} <- :ets.tab2list(table()),
          kill.host == host,
          kill.at >= since,
          (kill.scope == "session" and kill.sid == Map.get(match, :harness_session_id)) or
            (kill.scope == "adapter" and kill.key == Map.get(match, :adapter_key)),
          do: kill

    case Enum.sort_by(recorded, & &1.at) do
      [kill | _] -> Map.take(kill, [:limit, :scope, :bytes, :limit_bytes, :mode])
      [] -> enforced_counters(match)
    end
  rescue
    ArgumentError -> nil
  end

  @doc """
  The last recorded exit of an adapter launch (`128 + signal` for a signal,
  as the helper reports it) and whether host available was below the floor
  then (R15). Written by `Acp.Conn` before it fails pending prompts.
  """
  @spec adapter_exit(String.t() | nil) :: map() | nil
  def adapter_exit(nil), do: nil

  def adapter_exit(launch_id) do
    case lookup({:adapter_exit, launch_id}) do
      [{_, exit}] -> exit
      _ -> nil
    end
  end

  @doc false
  @spec note_adapter_exit(String.t() | nil, integer()) :: :ok
  def note_adapter_exit(nil, _status), do: :ok

  def note_adapter_exit(launch_id, status) do
    low? =
      case Enum.find(:ets.tab2list(table()), &match?({{:host, _}, %{local: true}}, &1)) do
        {_, %{available: available, settings: %{floor_hold: hold}}} when is_number(available) ->
          available < hold

        _ ->
          nil
      end

    :ets.insert(
      table(),
      {{:adapter_exit, launch_id},
       %{status: status, at: System.system_time(:millisecond), host_low: low?}}
    )

    :ok
  rescue
    ArgumentError -> :ok
  end

  @doc """
  The environment a local adapter launch of `key` needs so its session
  processes start through the launch step (AS2), and, in `enforced` mode, the
  adapter's own unit (R12c). Empty when the guard does not apply.
  """
  @spec launch_env(tuple(), String.t(), keyword(), DB.server()) :: [{String.t(), String.t()}]
  def launch_env({harness, _preset, host}, launch_id, opts, db \\ DB) do
    with %{local: true, mode: mode} = view when mode in ["watched", "enforced"] <- host_view(host),
         nil <- Keyword.get(opts, :process_ssh) do
      module = Harness.module!(harness)
      env = Keyword.get(opts, :env, [])

      session_env =
        if Harness.session_processes?(module) and is_binary(view.step) do
          case module.session_process_executable(Keyword.get(opts, :cmd, []), env) do
            {:ok, %{env_name: name, executable: executable}} ->
              [
                {name, view.step},
                {"TIGHTBEAM_SESSION_EXEC_TARGET", executable},
                {"TIGHTBEAM_MEMORY_GUARD_DIR", view.dir},
                {"TIGHTBEAM_ADAPTER_LAUNCH_ID", launch_id}
              ]

            {:error, reason} ->
              EventLog.lifecycle(
                db,
                "memory_guard_launch_unplaced",
                host,
                JSON.encode!(%{host: host, launchId: launch_id, error: reason})
              )

              []
          end
        else
          []
        end

      adapter_env =
        case {mode, view.layout} do
          {"enforced", %{} = layout} ->
            case Cgroup.create_adapter_unit(layout, launch_id) do
              {:ok, unit} ->
                [{"TIGHTBEAM_ADAPTER_CGROUP", Cgroup.dir(layout.fs, unit)}]

              {:error, reason} ->
                EventLog.lifecycle(
                  db,
                  "memory_guard_launch_unplaced",
                  host,
                  JSON.encode!(%{host: host, launchId: launch_id, error: reason})
                )

                []
            end

          _ ->
            []
        end

      session_env ++ adapter_env
    else
      _ -> []
    end
  rescue
    ArgumentError -> []
  end

  ## Server API

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  def child_spec(opts),
    do: %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}, restart: :permanent}

  @doc """
  Admission for the next queued turn of `session_key` (R3, R5, R2, R6):
  `:ok`, or `{:held, details}` when the turn needs a launch the host cannot
  take now. A held turn stays `queued`; the guard nudges its lane when it can
  run. The call may wait for an idle session process to close first.
  """
  @spec admit(String.t()) :: :ok | :no_turn | {:held, [String.t()]}
  def admit(session_key) do
    if running?(), do: GenServer.call(__MODULE__, {:admit, session_key}, 120_000), else: :ok
  catch
    :exit, _ -> :ok
  end

  @doc "A turn of `session_key` ended; its reservation, if unused, is released."
  @spec turn_finished(String.t()) :: :ok
  def turn_finished(session_key) do
    if running?(), do: GenServer.cast(__MODULE__, {:turn_finished, session_key})
    :ok
  end

  @doc "An adapter's residency (its `known` sessions) changed."
  @spec residency(pid(), tuple(), String.t() | nil, MapSet.t()) :: :ok
  def residency(adapter, key, launch_id, known) do
    if running?(), do: GenServer.cast(__MODULE__, {:residency, adapter, key, launch_id, known})
    :ok
  end

  @doc """
  R2a: the adapter launch `launch_id` of `key` ended. Every session tree it
  started is ended before this returns, so no replacement adapter starts while
  one lives.
  """
  @spec adapter_ended(tuple(), String.t() | nil) :: :ok
  def adapter_ended(key, launch_id) do
    if running?(), do: GenServer.call(__MODULE__, {:adapter_ended, key, launch_id}, 60_000)
    :ok
  catch
    :exit, _ -> :ok
  end

  @doc "R2a backstop before a launch of `key`: no session tree of an earlier launch survives."
  @spec ensure_no_orphans(tuple()) :: :ok
  def ensure_no_orphans(key) do
    if running?(), do: GenServer.call(__MODULE__, {:ensure_no_orphans, key}, 60_000)
    :ok
  catch
    :exit, _ -> :ok
  end

  @doc "A host's settings changed (R17): re-determine its mode and apply them."
  @spec settings_changed(String.t()) :: :ok
  def settings_changed(host) do
    if running?(), do: GenServer.call(__MODULE__, {:settings_changed, host}, 30_000)
    :ok
  catch
    :exit, _ -> :ok
  end

  @doc """
  The host-capacity reasons that would hold `session_key`'s next turn now,
  for the held-state read (R7): `[%{detail, host, since, condition}]`.
  """
  @spec hold_reasons(String.t()) :: [map()]
  def hold_reasons(session_key) do
    if running?(), do: GenServer.call(__MODULE__, {:hold_reasons, session_key}, 10_000), else: []
  catch
    :exit, _ -> []
  end

  @doc "The supported host read (R12b)."
  @spec read(String.t()) :: map() | nil
  def read(host) do
    if running?(), do: GenServer.call(__MODULE__, {:read, host}, 10_000)
  catch
    :exit, _ -> nil
  end

  @doc "Run one sampling pass now (tests and the boot pass)."
  def tick, do: GenServer.call(__MODULE__, :tick, 60_000)

  ## Server

  @impl true
  def init(opts) do
    ensure_table()
    db = Keyword.get(opts, :db, DB)
    base_dir = Keyword.fetch!(opts, :base_dir)
    root = Keyword.get(opts, :root, "/")

    state = %{
      db: db,
      base_dir: base_dir,
      cli_bin: Keyword.get(opts, :cli_bin),
      local_host: Keyword.get(opts, :local_host, Placement.local_host_name()),
      root: root,
      fs: Keyword.get(opts, :cgroup_fs, Path.join(root, "sys/fs/cgroup")),
      probe: Keyword.get(opts, :probe, fn -> Probe.probe(root: root) end),
      sample_ms: Keyword.get(opts, :sample_ms, 1_000),
      clock: Keyword.get(opts, :clock, fn -> System.system_time(:millisecond) end),
      closer: Keyword.get(opts, :closer, &default_close/3),
      idle_check: Keyword.get(opts, :idle_check, &default_idle_check/2),
      killer: Keyword.get(opts, :killer, &default_kill/2),
      nudge: Keyword.get(opts, :nudge, &default_nudge/1),
      conn_registry: Keyword.get(opts, :conn_registry, Tightbeam.ConnRegistry),
      hosts: %{},
      adapters: %{},
      launches: %{},
      busy: %{},
      reservations: %{},
      last_used: %{},
      held: %{},
      closing: %{},
      # Sessions found busy at close time; skipped until their state changes.
      unclosable: MapSet.new(),
      killing: %{},
      announced: MapSet.new()
    }

    state = state |> determine_all() |> publish_all()

    if state.sample_ms != :manual, do: Process.send_after(self(), :tick, state.sample_ms)
    {:ok, state}
  end

  @impl true
  def handle_call({:admit, session_key}, from, state) do
    case admission(state, session_key) do
      {:ok, state} ->
        {:reply, :ok, publish_all(state)}

      {:held, details, state} ->
        {:reply, {:held, details}, publish_all(state)}

      {:no_turn, state} ->
        {:reply, :no_turn, state}

      {:closing, ref, state} ->
        # The reply waits for the idle close; the lane's call is blocked, the
        # guard is not.
        {:noreply, add_waiter(state, ref, session_key, from)}
    end
  end

  def handle_call({:adapter_ended, key, launch_id}, _from, state) do
    state = end_adapter_sessions(state, key, launch_id)
    {:reply, :ok, publish_all(state)}
  end

  def handle_call({:ensure_no_orphans, key}, _from, state) do
    state = end_adapter_sessions(state, key, :any_previous)
    {:reply, :ok, state}
  end

  def handle_call({:settings_changed, host}, _from, state) do
    state = state |> determine(host) |> publish_all() |> trim_to_cap(host) |> release_check(host)
    {:reply, :ok, state}
  end

  def handle_call({:hold_reasons, session_key}, _from, state) do
    {:reply, evaluate_reasons(state, session_key), state}
  end

  def handle_call({:read, host}, _from, state) do
    {:reply, supported_read(state, host), state}
  end

  def handle_call(:tick, _from, state) do
    {:reply, :ok, sample(%{state | unclosable: MapSet.new()})}
  end

  @impl true
  def handle_cast({:turn_finished, session_key}, state) do
    state = %{state | unclosable: MapSet.new()}
    host = Map.get(state.busy, session_key) || get_in(state.reservations, [session_key, :host])
    state = %{state | busy: Map.delete(state.busy, session_key)}
    state = %{state | reservations: Map.delete(state.reservations, session_key)}
    state = touch_session(state, session_key)
    state = if host, do: state |> trim_to_cap(host) |> release_check(host), else: state
    {:noreply, publish_all(state)}
  end

  def handle_cast({:residency, adapter, {_, _, host} = key, launch_id, known}, state) do
    entry =
      case Map.fetch(state.adapters, adapter) do
        {:ok, entry} ->
          %{entry | sids: known, launch_id: launch_id || entry.launch_id}

        :error ->
          %{
            key: key,
            host: host,
            sids: known,
            launch_id: launch_id,
            monitor: Process.monitor(adapter)
          }
      end

    added =
      MapSet.difference(
        known,
        Map.get(Map.get(state.adapters, adapter, %{}), :sids, MapSet.new())
      )

    now = state.clock.()
    last_used = Enum.reduce(added, state.last_used, &Map.put(&2, {host, &1}, now))
    state = %{state | adapters: Map.put(state.adapters, adapter, entry), last_used: last_used}
    {:noreply, state |> release_check(host) |> publish_all()}
  end

  @impl true
  def handle_info(:tick, state) do
    state = sample(%{state | unclosable: MapSet.new()})
    Process.send_after(self(), :tick, state.sample_ms)
    {:noreply, state}
  end

  def handle_info({:DOWN, monitor, :process, adapter, _reason}, state) do
    case Map.fetch(state.adapters, adapter) do
      {:ok, %{monitor: ^monitor, host: host}} ->
        state = %{state | adapters: Map.delete(state.adapters, adapter)}
        {:noreply, state |> release_check(host) |> publish_all()}

      _ ->
        {:noreply, state}
    end
  end

  def handle_info({:closed, ref, result}, state) do
    case Map.pop(state.closing, ref) do
      {nil, _} ->
        {:noreply, state}

      {closing, rest} ->
        state = %{state | closing: rest}
        state = finish_close(state, closing, result)
        state = if result == :ok, do: trim_to_cap(state, closing.host), else: state
        {:noreply, publish_all(state)}
    end
  end

  def handle_info({:killed, id, _result}, state) do
    {:noreply, %{state | killing: Map.delete(state.killing, id)}}
  end

  def handle_info(_message, state), do: {:noreply, state}

  ## Modes and settings

  defp determine_all(state) do
    hosts = Map.keys(Placement.hosts(state.base_dir, state.db))
    Enum.reduce(Enum.uniq([state.local_host | hosts]), state, &determine(&2, &1))
  end

  defp determine(state, host) do
    local? = host == state.local_host
    stored = Settings.stored(state.db, host)
    previous = Map.get(state.hosts, host)

    probe =
      cond do
        not local? ->
          %{
            mode: :count_only,
            reason:
              "only the resident cap applies on a remote host; memory limits run on the gateway's own host",
            mem_total: nil,
            cgroup: nil
          }

        previous && previous.probe ->
          previous.probe

        true ->
          state.probe.()
      end

    settings = Settings.effective(stored, probe.mem_total)

    {mode, reason, layout} =
      cond do
        settings.mode == "off" ->
          {"off", "an admin turned memory limits off for this host", nil}

        probe.mode == :enforced ->
          existing = previous && previous.layout

          result =
            if existing,
              do: with(:ok <- Cgroup.set_budget(existing, settings.budget), do: {:ok, existing}),
              else: Cgroup.setup(state.fs, probe.cgroup, settings.budget)

          case result do
            {:ok, layout} ->
              {"enforced", nil, layout}

            {:error, error} ->
              {"watched",
               "per-agent memory limits are checked every second, not enforced by the kernel: " <>
                 error, nil}
          end

        probe.mode == :watched ->
          {"watched", probe.reason, nil}

        true ->
          {"count-only", probe.reason, nil}
      end

    mode =
      if previous != nil and previous.sampling_failed and mode in ["watched", "enforced"],
        do: "count-only",
        else: mode

    step =
      if local? and mode in ["watched", "enforced"] do
        case Records.install_step(state.base_dir, state.cli_bin) do
          {:ok, link} ->
            link

          {:error, error} ->
            Logger.warning("memory guard: session launch step unavailable: #{error}")
            nil
        end
      end

    if local? do
      _ =
        Records.publish_config(state.base_dir, %{
          mode: mode,
          fs: layout && layout.fs,
          harness: layout && layout.harness,
          sessionLimit: settings.session_limit,
          oomScoreAdj: settings.session_oom_score_adj
        })
    end

    host_state = %{
      local: local?,
      probe: probe,
      mode: mode,
      reason: reason,
      settings: settings,
      layout: layout,
      step: step,
      available: previous && previous.available,
      floor_held: (previous && previous.floor_held) || false,
      floor_since: previous && previous.floor_since,
      total: previous && previous.total,
      budget_held: (previous && previous.budget_held) || false,
      budget_since: previous && previous.budget_since,
      sampling_failed: (previous && previous.sampling_failed) || false
    }

    changed? =
      is_nil(previous) or previous.mode != mode or previous.reason != reason or
        previous.settings != settings

    if changed? do
      EventLog.lifecycle(
        state.db,
        "memory_guard_mode",
        host,
        JSON.encode!(%{
          host: host,
          mode: mode,
          reason: reason,
          settings: settings_json(settings),
          invalid: settings.invalid
        })
      )
    end

    %{state | hosts: Map.put(state.hosts, host, host_state)}
  end

  defp settings_json(settings) do
    %{
      mode: settings.mode,
      budget: settings.budget,
      sessionLimit: settings.session_limit,
      residentCap: settings.resident_cap,
      floorHold: settings.floor_hold,
      floorRelease: settings.floor_release,
      sessionOomScoreAdj: settings.session_oom_score_adj,
      memTotal: settings.mem_total
    }
  end

  ## Admission

  defp admission(state, session_key) do
    with %{} = session <- Org.get(state.db, session_key),
         %{} = host_state <- Map.get(state.hosts, session.host) || :unknown_host,
         seq when is_integer(seq) <- oldest_queued(state.db, session_key) do
      if host_state.mode == "off" do
        {:ok, mark_busy(state, session_key, session.host)}
      else
        decide(state, session, host_state, seq)
      end
    else
      # No queued turn yet: nothing is decided, so the lane claims nothing. A
      # turn queued after this answer nudges the lane, which asks again;
      # claiming it now would admit a launch nobody checked.
      nil -> {:no_turn, state}
      _ -> {:ok, state}
    end
  end

  defp decide(state, session, host_state, seq) do
    launch = launch_needed(state, session)
    reserved? = reserved_main?(state, session)

    if launch == :none do
      state =
        state
        |> resume_if_held(session.session_key)
        |> mark_busy(session.session_key, session.host)

      {:ok, state}
    else
      host_reasons = host_level_reasons(host_state)

      # R3b: the reserved Main takes its reserved slot; R3 never holds it. The
      # floor and the budget still do.
      {cap_reason, state} =
        if reserved? and match?({:session, _}, launch),
          do: {nil, state},
          else: cap_decision(state, session, host_state, launch, seq, host_reasons)

      cond do
        match?({:closing, _}, cap_reason) ->
          {:closing, elem(cap_reason, 1), state}

        host_reasons != [] or cap_reason != nil ->
          details = host_reasons ++ List.wrap(cap_reason)
          {:held, details, hold(state, session, seq, details)}

        true ->
          state =
            state
            |> reserve(session, launch, reserved?)
            |> resume_if_held(session.session_key)
            |> mark_busy(session.session_key, session.host)

          {:ok, state}
      end
    end
  end

  defp host_level_reasons(%{mode: mode} = host_state) when mode in ["watched", "enforced"] do
    Enum.filter(
      [
        host_state.floor_held && "memory_floor",
        host_state.budget_held && "memory_budget"
      ],
      & &1
    )
  end

  defp host_level_reasons(_host_state), do: []

  # :none — resident; {:session, sid | nil} — a session process launch;
  # :adapter — an adapter launch only (a harness without session processes).
  defp launch_needed(state, session) do
    harness = Harness.parse!(session.harness)
    harness_id = harness.id()
    key = {harness_id, "shared", session.host}
    adapter = Enum.find(state.adapters, fn {_pid, entry} -> entry.key == key end)
    session_processes? = Harness.session_processes?(harness)
    sid = current_sid(state.db, session.session_key)

    cond do
      not session_processes? and adapter != nil -> :none
      not session_processes? -> :adapter
      adapter != nil and is_binary(sid) and MapSet.member?(elem(adapter, 1).sids, sid) -> :none
      true -> {:session, sid}
    end
  end

  defp current_sid(db, session_key) do
    case Org.current_pointer(db, session_key) do
      %{harness_session_id: sid} -> sid
      _ -> nil
    end
  end

  defp cap_decision(state, _session, _host_state, :adapter, _seq, _host_reasons), do: {nil, state}

  defp cap_decision(state, session, host_state, {:session, _sid}, seq, host_reasons) do
    case host_state.settings.resident_cap do
      nil ->
        {nil, state}

      cap ->
        count = resident_count(state, session.host, session.session_key)
        ahead = waiting_ahead(state, session, seq)

        cond do
          # R3a: free slots go to sessions ahead in line first (a Main, then a
          # user-facing session, then the oldest worker).
          count + ahead < cap ->
            {nil, state}

          host_reasons != [] ->
            # The floor or budget holds anyway. The cap is a reason only when it
            # is really full, and closing for it now would shed a process for a
            # launch that cannot run.
            {if(count >= cap, do: "resident_cap"), state}

          ahead > 0 ->
            {"resident_cap", state}

          true ->
            case start_close(state, session.host, "resident_cap") do
              {:ok, ref, state} -> {{:closing, ref}, state}
              :none -> {"resident_cap", state}
            end
        end
    end
  end

  # R3a: how many sessions waiting for a launch on this host go before
  # `session` (class first, then the oldest waiting turn).
  defp waiting_ahead(state, session, seq) do
    mine = {Priority.rank(Priority.class(state.db, session)), seq}

    state
    |> waiters(session.host, session.session_key)
    |> Enum.count(fn {_key, place} -> place < mine end)
  end

  # Sessions on `host` still waiting for a launch, each with its place
  # `{class rank, oldest queued seq}`: held here, a turn still queued, no other
  # standing reason (R6a: priority never admits past a park), and not the
  # reserved Main, which never competes for a slot under the cap (R3b).
  defp waiters(state, host, exclude) do
    reserved = reserved_main_key(state)

    for {key, %{host: ^host}} <- state.held,
        key != exclude,
        key != reserved,
        seq <- [oldest_queued(state.db, key)],
        is_integer(seq),
        Admission.other_reasons(state.db, key) == [],
        %{} = session <- [Org.get(state.db, key)] do
      {key, {Priority.rank(Priority.class(state.db, session)), seq}}
    end
    |> Enum.sort_by(&elem(&1, 1))
  end

  defp reserved_main_key(state) do
    case Priority.reserved_main(state.db) do
      %{session_key: key} -> key
      nil -> nil
    end
  end

  defp reserved_main?(state, session),
    do: is_binary(session.session_key) and session.session_key == reserved_main_key(state)

  defp resident_sids(state, host) do
    state.adapters
    |> Map.values()
    |> Enum.filter(&(&1.host == host and Harness.session_processes?(harness_module(&1.key))))
    |> Enum.flat_map(&MapSet.to_list(&1.sids))
    |> MapSet.new()
  end

  # The reserved Main's process, when it is resident on `host` (R3b).
  defp reserved_sid(state, host) do
    with key when is_binary(key) <- reserved_main_key(state),
         sid when is_binary(sid) <- current_sid(state.db, key),
         true <- MapSet.member?(resident_sids(state, host), sid) do
      sid
    else
      _ -> nil
    end
  end

  # Resident session processes under the cap on the host plus slots reserved
  # for launches in flight, without `session_key` itself. The reserved Main's
  # process holds the reserved slot and is not counted (R3).
  defp resident_count(state, host, exclude_session) do
    resident = MapSet.delete(resident_sids(state, host), reserved_sid(state, host))

    reserved =
      Enum.count(state.reservations, fn {key, reservation} ->
        key != exclude_session and reservation.host == host and not reservation.reserved and
          not (is_binary(reservation.sid) and MapSet.member?(resident, reservation.sid)) and
          not (is_binary(sid = current_sid(state.db, key)) and MapSet.member?(resident, sid))
      end)

    MapSet.size(resident) + reserved
  end

  defp harness_module({harness, _, _}), do: Harness.module!(harness)

  defp reserve(state, session, {:session, sid}, reserved?) do
    %{
      state
      | reservations:
          Map.put(state.reservations, session.session_key, %{
            host: session.host,
            sid: sid,
            reserved: reserved?,
            at: state.clock.()
          })
    }
  end

  defp reserve(state, _session, _launch, _reserved?), do: state

  defp mark_busy(state, session_key, host) do
    %{state | busy: Map.put(state.busy, session_key, host)}
  end

  defp touch_session(state, session_key) do
    case Org.get(state.db, session_key) do
      %{host: host} ->
        case current_sid(state.db, session_key) do
          sid when is_binary(sid) ->
            %{state | last_used: Map.put(state.last_used, {host, sid}, state.clock.())}

          _ ->
            state
        end

      _ ->
        state
    end
  end

  defp oldest_queued(db, session_key) do
    case DB.query(
           db,
           "SELECT seq FROM turns WHERE sessionKey=?1 AND status='queued' ORDER BY seq LIMIT 1",
           [session_key]
         ) do
      {:ok, [[seq]]} -> seq
      _ -> nil
    end
  end

  ## Holds (R6, R6a, R7)

  defp hold(state, session, seq, details) do
    now = state.clock.()

    previous =
      Map.get(state.held, session.session_key, %{details: %{}, host: session.host, seq: seq})

    new_details =
      Map.new(details, fn detail -> {detail, Map.get(previous.details, detail, now)} end)

    for detail <- details, not Map.has_key?(previous.details, detail) do
      EventLog.lifecycle(
        state.db,
        "memory_guard_hold",
        session.session_key,
        JSON.encode!(%{
          host: session.host,
          reasonClass: "host_capacity",
          detail: detail,
          since: now,
          condition: condition(state, session.host, detail)
        })
      )
    end

    held = %{host: session.host, seq: seq, details: new_details}
    state = %{state | held: Map.put(state.held, session.session_key, held)}

    # R7: a user-originated turn that becomes held gets one plain-words
    # marker in its own conversation, once per hold.
    if previous.details == %{} and
         Priority.user_originated_pending?(state.db, session.session_key),
       do: waiting_marker(state, session, hd(details))

    state
  end

  defp waiting_marker(state, session, detail) do
    host = session.host
    host_state = Map.fetch!(state.hosts, host)
    place = place_in_line(state, session)

    line =
      "You are #{ordinal(place)} in line" <>
        if(detail == "resident_cap", do: ", and nothing was stopped to make room.", else: ".")

    message =
      case detail do
        "resident_cap" ->
          "Waiting for a free agent slot on #{host}: all #{host_state.settings.resident_cap} are busy with other work. " <>
            line

        "memory_floor" ->
          "Waiting for #{host} to have more free memory (now #{fmt(host_state.available)}%, starts at #{fmt(host_state.settings.floor_release)}%). " <>
            line

        "memory_budget" ->
          "Waiting for Tightbeam's agents on #{host} to use less memory (now #{gib(host_state.total)} of a #{gib(host_state.settings.budget)} budget). " <>
            line
      end

    EventLog.notice(
      state.db,
      "memory_guard_waiting",
      session.session_key,
      JSON.encode!(%{host: host, detail: detail, placeInLine: place}),
      audience: {:session, session.session_key},
      message: message,
      attention: :normal,
      conn_registry: state.conn_registry
    )
  rescue
    error ->
      Logger.warning("memory guard: waiting marker not posted: #{Exception.message(error)}")
  catch
    :exit, reason -> Logger.warning("memory guard: waiting marker not posted: #{inspect(reason)}")
  end

  defp ordinal(1), do: "first"
  defp ordinal(2), do: "second"
  defp ordinal(3), do: "third"
  defp ordinal(n), do: "number #{n}"

  # 1-based place among the sessions waiting for a launch on its host (R3a).
  defp place_in_line(state, session) do
    case oldest_queued(state.db, session.session_key) do
      nil ->
        1

      seq ->
        mine = {Priority.rank(Priority.class(state.db, session)), seq}

        ahead =
          state |> waiters(session.host, session.session_key) |> Enum.count(&(elem(&1, 1) < mine))

        ahead + 1
    end
  end

  defp resume_if_held(state, session_key) do
    case Map.pop(state.held, session_key) do
      {nil, _} ->
        state

      {held, rest} ->
        EventLog.lifecycle(
          state.db,
          "admission_resumed",
          session_key,
          JSON.encode!(%{host: held.host, after: Map.keys(held.details)})
        )

        %{state | held: rest}
    end
  end

  # After anything that can free capacity: nudge held sessions oldest first.
  # Each lane re-asks `admit/1`, which keeps the oldest-first order (a younger
  # turn waits while an older one holds the same detail).
  defp release_check(state, host) do
    reserved = reserved_main_key(state)

    if Map.has_key?(state.held, reserved) and Map.get(state.held, reserved).host == host,
      do: state.nudge.(reserved)

    state
    |> waiters(host, reserved)
    |> Enum.each(fn {key, _place} -> state.nudge.(key) end)

    state
  end

  defp evaluate_reasons(state, session_key) do
    with %{} = session <- Org.get(state.db, session_key),
         %{} = host_state <- Map.get(state.hosts, session.host),
         true <- host_state.mode != "off",
         launch when launch != :none <- launch_needed(state, session) do
      held = Map.get(state.held, session_key, %{details: %{}})
      now = state.clock.()

      # R3b/R7: the reserved Main is never held by the cap.
      details =
        host_level_reasons(host_state) ++
          if(
            match?({:session, _}, launch) and not reserved_main?(state, session) and
              cap_full?(state, session, host_state),
            do: ["resident_cap"],
            else: []
          )

      class =
        if reserved_main?(state, session), do: "main", else: Priority.class(state.db, session)

      place = place_in_line(state, session)

      for detail <- details do
        %{
          reasonClass: "host_capacity",
          detail: detail,
          host: session.host,
          since: Map.get(held.details, detail, since(host_state, detail, now)),
          condition: condition(state, session.host, detail),
          priorityClass: class,
          placeInLine: place
        }
      end
    else
      _ -> []
    end
  end

  defp cap_full?(state, session, host_state) do
    case host_state.settings.resident_cap do
      nil ->
        false

      cap ->
        resident_count(state, session.host, session.session_key) >= cap and
          idle_candidates(state, session.host, "resident_cap") == []
    end
  end

  defp since(%{floor_since: since}, "memory_floor", _now) when is_integer(since), do: since
  defp since(%{budget_since: since}, "memory_budget", _now) when is_integer(since), do: since
  defp since(_host_state, _detail, now), do: now

  @doc false
  def condition(state, host, detail) do
    host_state = Map.get(state.hosts, host)

    case detail do
      "memory_floor" ->
        "starts when #{host} has #{fmt(host_state.settings.floor_release)}% of memory free; now #{fmt(host_state.available)}%"

      "memory_budget" ->
        "starts when Tightbeam's agents on #{host} use less than 85% of their #{gib(host_state.settings.budget)} memory budget; now #{gib(host_state.total)}"

      "resident_cap" ->
        "starts when one of #{host_state.settings.resident_cap} agent processes on #{host} becomes free"
    end
  end

  defp fmt(nil), do: "unknown"
  defp fmt(number) when is_integer(number), do: Integer.to_string(number)
  defp fmt(number), do: :erlang.float_to_binary(number * 1.0, decimals: 1)

  defp gib(nil), do: "unknown"
  defp gib(bytes), do: :erlang.float_to_binary(bytes / @gib, decimals: 1) <> " GiB"

  ## Idle close (R4)

  # R3a: idle workers first (least recently used first), then idle
  # user-facing processes, an idle Main last. R3 never closes the reserved
  # Main in its slot: that frees no slot under the cap (R3b).
  defp idle_candidates(state, host, reason) do
    closing = MapSet.new(Map.values(state.closing), &{&1.host, &1.sid})
    reserved = if reason == "resident_cap", do: reserved_sid(state, host)

    for {adapter, entry} <- state.adapters,
        entry.host == host,
        Harness.session_processes?(harness_module(entry.key)),
        sid <- entry.sids,
        not MapSet.member?(closing, {host, sid}),
        not MapSet.member?(state.unclosable, {host, sid}),
        sid != reserved,
        session_key <- [session_for_sid(state.db, sid)],
        not Map.has_key?(state.busy, session_key),
        not Map.has_key?(state.reservations, session_key),
        is_nil(session_key) or not turn_pending?(state.db, session_key) do
      {close_rank(state, session_key), Map.get(state.last_used, {host, sid}, 0), adapter, sid,
       session_key}
    end
    |> Enum.sort()
  end

  defp close_rank(_state, nil), do: 0

  defp close_rank(state, session_key) do
    case Org.get(state.db, session_key) do
      nil -> 0
      session -> 2 - Priority.rank(Priority.class(state.db, session))
    end
  end

  defp session_for_sid(db, sid) do
    case DB.query(
           db,
           """
           SELECT sessionKey FROM harness_pointers
           WHERE harnessSessionId=?1
           ORDER BY id DESC LIMIT 1
           """,
           [sid]
         ) do
      {:ok, [[key]]} -> key
      _ -> nil
    end
  rescue
    _ -> nil
  end

  defp turn_pending?(db, session_key) do
    case DB.query(
           db,
           "SELECT 1 FROM turns WHERE sessionKey=?1 AND status IN ('queued','running') LIMIT 1",
           [session_key]
         ) do
      {:ok, [[1]]} -> true
      _ -> false
    end
  end

  # Start closing the least recently used idle session process. Returns :none
  # when no session process is idle.
  defp start_close(state, host, reason) do
    case idle_candidates(state, host, reason) do
      [] ->
        :none

      [{_rank, _used, adapter, sid, session_key} | _] ->
        guard = self()
        ref = make_ref()
        closer = state.closer
        idle_check = state.idle_check

        Task.start(fn ->
          result =
            case idle_check.(adapter, sid) do
              :idle -> closer.(adapter, sid, reason)
              other -> {:error, {:not_idle, other}}
            end

          send(guard, {:closed, ref, result})
        end)

        closing = %{
          host: host,
          sid: sid,
          adapter: adapter,
          session_key: session_key,
          reason: reason,
          waiters: []
        }

        {:ok, ref, %{state | closing: Map.put(state.closing, ref, closing)}}
    end
  end

  defp add_waiter(state, ref, session_key, from) do
    update_in(state.closing[ref].waiters, &(&1 ++ [{session_key, from}]))
  end

  defp finish_close(state, closing, result) do
    state =
      case result do
        :ok ->
          EventLog.lifecycle(
            state.db,
            "memory_guard_idle_closed",
            closing.session_key || closing.sid,
            JSON.encode!(%{host: closing.host, sessionId: closing.sid, reason: closing.reason})
          )

          # The close cleared the adapter's residency; reflect it now rather
          # than waiting for the adapter's own residency report.
          adapters =
            Map.update!(state.adapters, closing.adapter, fn entry ->
              %{entry | sids: MapSet.delete(entry.sids, closing.sid)}
            end)

          %{state | adapters: adapters}

        _ ->
          # Not idle after all (an observed background task, a prompt that
          # arrived) or the close failed: it stays resident and is not picked
          # again until a turn ends or the next sample.
          %{state | unclosable: MapSet.put(state.unclosable, {closing.host, closing.sid})}
      end

    Enum.reduce(closing.waiters, state, fn {session_key, from}, acc ->
      case admission(acc, session_key) do
        {:ok, acc} ->
          GenServer.reply(from, :ok)
          acc

        {:held, details, acc} ->
          GenServer.reply(from, {:held, details})
          acc

        {:no_turn, acc} ->
          GenServer.reply(from, :no_turn)
          acc

        {:closing, ref, acc} ->
          add_waiter(acc, ref, session_key, from)
      end
    end)
  end

  defp default_idle_check(adapter, sid), do: Tightbeam.Acp.Adapter.idle_session?(adapter, sid)

  defp default_close(adapter, sid, _reason) do
    case Tightbeam.Acp.Adapter.close_session(adapter, sid) do
      :ok -> :ok
      other -> other
    end
  end

  defp default_nudge(session_key) do
    case Process.whereis(Tightbeam.LaneManager) do
      nil -> Tightbeam.SessionLane.nudge(session_key)
      _ -> Tightbeam.LaneManager.ensure_lane(session_key)
    end
  end

  ## Sampling (R1, R2, R5) and kernel kills

  defp sample(state) do
    host = state.local_host

    case Map.get(state.hosts, host) do
      %{mode: mode} = host_state when mode in ["watched", "enforced"] ->
        state
        |> refresh_launches()
        |> sample_host(host, host_state)
        |> expire_kills()
        |> publish_all()

      %{mode: "count-only", sampling_failed: true} ->
        # R12a: retry the read; the host returns to its mode once it succeeds.
        case measure(state, host, %{Map.get(state.hosts, host) | mode: "watched"}) do
          {:ok, _} ->
            state = put_in(state.hosts[host].sampling_failed, false)
            state |> determine(host) |> publish_all()

          :error ->
            state
        end

      _ ->
        state
    end
  end

  defp refresh_launches(state) do
    %{state | launches: Records.read_all(state.base_dir)}
  end

  defp sample_host(state, host, host_state) do
    settings = host_state.settings

    available =
      case Probe.available_percent(state.root) do
        {:ok, percent} -> percent
        :error -> nil
      end

    case measure(state, host, host_state) do
      {:ok, measured} ->
        now = state.clock.()
        state = floor_transition(state, host, available, now)
        state = budget_transition(state, host, measured.total, now)
        state = put_in(state.hosts[host].total, measured.total)
        state = put_in(state.hosts[host].available, available)
        state = watched_limits(state, host, measured, settings)
        state = observe_ended(state, host, measured)
        state |> shed(host) |> trim_to_cap(host)

      :error ->
        if host_state.sampling_failed do
          state
        else
          EventLog.lifecycle(
            state.db,
            "memory_guard_sampling_failed",
            host,
            JSON.encode!(%{host: host, mode: host_state.mode})
          )

          state = put_in(state.hosts[host].sampling_failed, true)
          state = put_in(state.hosts[host].mode, "count-only")

          put_in(
            state.hosts[host].reason,
            "tree memory cannot be read; only the resident cap applies until a read succeeds"
          )
        end
    end
  end

  # Per unit: %{id, scope, sid?, key?, launch_id, bytes, limit_bytes, pids?, unit?}
  defp measure(state, host, host_state) do
    adapters = local_adapters(state, host)

    case host_state.mode do
      "enforced" ->
        measure_enforced(state, host_state, adapters)

      "watched" ->
        measure_watched(state, adapters, Map.values(state.launches))
    end
  end

  defp local_adapters(state, host) do
    rows = HarnessProcess.list(state.db)

    for row <- rows,
        row.host == host,
        is_nil(row.ssh),
        row.state == "running",
        is_integer(row.os_pid),
        do: row
  rescue
    _ -> []
  end

  defp measure_watched(state, adapters, launches) do
    case ProcTree.snapshot(state.root) do
      {:ok, table} ->
        sessions =
          for record <- launches,
              alive?(table, record),
              do: record

        session_trees = ProcTree.trees(table, Enum.map(sessions, & &1["pid"]))
        in_sessions = session_trees |> Map.values() |> Enum.reduce(MapSet.new(), &MapSet.union/2)

        session_units =
          for record <- sessions do
            pids = Map.fetch!(session_trees, record["pid"])

            %{
              id: "session:" <> record["launchId"],
              scope: "session",
              sid: record["sessionId"],
              launch_id: record["launchId"],
              adapter_launch_id: record["adapterLaunchId"],
              bytes: ProcTree.bytes(table, pids),
              limit_bytes: record["sessionLimit"],
              record: record,
              pids: pids
            }
          end

        adapter_units =
          for row <- adapters do
            pids = MapSet.difference(ProcTree.tree(table, row.os_pid), in_sessions)

            %{
              id: "adapter:" <> row.launch_id,
              scope: "adapter",
              key: parse_key(row.adapter_key),
              launch_id: row.launch_id,
              bytes: ProcTree.bytes(table, pids),
              limit_bytes: nil,
              row: row,
              pids: pids
            }
          end

        units = session_units ++ adapter_units
        {:ok, %{units: units, total: Enum.sum(Enum.map(units, & &1.bytes)), table: table}}

      :error ->
        :error
    end
  end

  defp measure_enforced(state, host_state, adapters) do
    layout = host_state.layout

    case Cgroup.current(layout.fs, layout.harness) do
      {:ok, total} ->
        enforced_sessions =
          for {_id, record} <- state.launches,
              record["placement"] == "enforced",
              do: %{
                id: "session:" <> record["launchId"],
                scope: "session",
                sid: record["sessionId"],
                launch_id: record["launchId"],
                adapter_launch_id: record["adapterLaunchId"],
                unit: record["unit"],
                bytes: unit_bytes(layout, record["unit"]),
                limit_bytes: record["sessionLimit"],
                record: record
              }

        adapter_units =
          for row <- adapters do
            unit = Cgroup.adapter_unit(layout, row.launch_id)

            %{
              id: "adapter:" <> row.launch_id,
              scope: "adapter",
              key: parse_key(row.adapter_key),
              launch_id: row.launch_id,
              unit: unit,
              bytes: unit_bytes(layout, unit),
              limit_bytes: nil,
              row: row
            }
          end

        # A tree the kernel could not take (R12a: its cgroup failed) is
        # sampled and limited as in watched mode.
        unplaced = for {_id, r} <- state.launches, r["placement"] != "enforced", do: r

        watched =
          case unplaced do
            [] -> {:ok, %{units: []}}
            records -> measure_watched(state, [], records)
          end

        case watched do
          {:ok, %{units: watched_units}} ->
            units = enforced_sessions ++ adapter_units ++ watched_units
            {:ok, %{units: units, total: total + Enum.sum(Enum.map(watched_units, & &1.bytes))}}

          :error ->
            {:ok, %{units: enforced_sessions ++ adapter_units, total: total}}
        end

      :error ->
        :error
    end
  end

  defp unit_bytes(_layout, nil), do: 0

  defp unit_bytes(layout, unit) do
    case Cgroup.current(layout.fs, unit) do
      {:ok, bytes} -> bytes
      :error -> 0
    end
  end

  defp alive?(table, %{"pid" => pid, "start" => start}) when is_integer(pid) do
    case Map.fetch(table, pid) do
      {:ok, %{start: ^start}} -> true
      {:ok, _} -> is_nil(start)
      :error -> false
    end
  end

  defp alive?(_table, _record), do: false

  # A stored adapterKey name, "<harness>:<preset>@<host>", back to its key.
  defp parse_key(name) when is_binary(name) do
    case Regex.run(~r/^([^:]+):([^@]+)@(.+)$/, name) do
      [_, harness, preset, host] -> {Harness.parse!(harness).id(), preset, host}
      _ -> name
    end
  rescue
    _ -> name
  end

  defp parse_key(key), do: key

  # R5: hold below floorHold, release at floorRelease (hysteresis).
  defp floor_transition(state, _host, nil, _now), do: state

  defp floor_transition(state, host, available, now) do
    host_state = state.hosts[host]
    settings = host_state.settings

    cond do
      not host_state.floor_held and available < settings.floor_hold ->
        EventLog.lifecycle(
          state.db,
          "memory_guard_host_hold",
          host,
          JSON.encode!(%{host: host, detail: "memory_floor", available: available, at: now})
        )

        state
        |> put_in([:hosts, host, :floor_held], true)
        |> put_in([:hosts, host, :floor_since], now)

      host_state.floor_held and available >= settings.floor_release ->
        state
        |> put_in([:hosts, host, :floor_held], false)
        |> put_in([:hosts, host, :floor_since], nil)
        |> host_released(host, "memory_floor", %{available: available})

      true ->
        state
    end
  end

  # R2 approach: hold at 90% of the budget, release below 85%.
  defp budget_transition(state, host, total, now) do
    host_state = state.hosts[host]
    budget = host_state.settings.budget

    cond do
      is_nil(budget) ->
        state

      not host_state.budget_held and total >= budget * 0.9 ->
        EventLog.lifecycle(
          state.db,
          "memory_guard_host_hold",
          host,
          JSON.encode!(%{host: host, detail: "memory_budget", total: total, at: now})
        )

        state
        |> put_in([:hosts, host, :budget_held], true)
        |> put_in([:hosts, host, :budget_since], now)

      host_state.budget_held and total < budget * 0.85 ->
        state
        |> put_in([:hosts, host, :budget_held], false)
        |> put_in([:hosts, host, :budget_since], nil)
        |> host_released(host, "memory_budget", %{total: total})

      true ->
        state
    end
  end

  # One host-level reason released (R6a): record it, record what remains for
  # each held session and key, run the re-admission hooks deferred while it
  # stood once nothing stands, and nudge the held lanes.
  defp host_released(state, host, detail, facts) do
    remaining_host = host_level_reasons(state.hosts[host])

    EventLog.lifecycle(
      state.db,
      "memory_guard_release",
      host,
      JSON.encode!(Map.merge(facts, %{host: host, detail: detail, remaining: remaining_host}))
    )

    held_keys = for {key, held} <- state.held, held.host == host, do: key

    for session_key <- held_keys do
      other = Tightbeam.MemoryGuard.Admission.other_reasons(state.db, session_key)
      remaining = remaining_host ++ other

      if remaining != [] do
        EventLog.lifecycle(
          state.db,
          "admission_hold_remaining",
          session_key,
          JSON.encode!(%{host: host, released: detail, remaining: remaining})
        )
      end
    end

    if remaining_host == [] do
      :ok = Tightbeam.MemoryGuard.Admission.run_deferred(state.db, host)
    end

    release_check(state, host)
  end

  # R1 and R2 in watched mode (and for unplaced trees on an enforced host).
  defp watched_limits(state, host, measured, settings) do
    mode = state.hosts[host].mode
    units = measured.units

    over_session =
      Enum.find(units, fn unit ->
        unit.scope == "session" and is_integer(unit.limit_bytes) and unit.bytes > unit.limit_bytes and
          Map.has_key?(unit, :pids) and not Map.has_key?(state.killing, unit.id)
      end)

    cond do
      over_session != nil ->
        kill_unit(state, host, over_session, "session", mode)

      mode == "watched" and is_integer(settings.budget) and measured.total > settings.budget and
          map_size(state.killing) == 0 ->
        victim =
          units
          |> Enum.reject(&Map.has_key?(state.killing, &1.id))
          |> Enum.max_by(&rank(&1, settings.budget), fn -> nil end)

        if victim, do: kill_unit(state, host, victim, "budget", mode), else: state

      true ->
        state
    end
  end

  # As the kernel ranks inside a memory-limited group: tree memory, with each
  # session tree credited R14's +100 oom_score_adj (100/1000 of the budget).
  defp rank(%{scope: "session", bytes: bytes}, budget), do: bytes + div(budget, 10)
  defp rank(%{bytes: bytes}, _budget), do: bytes

  # R10a: the intent is recorded before the first signal.
  defp kill_unit(state, host, unit, limit, mode) do
    now = state.clock.()

    kill = %{
      host: host,
      scope: unit.scope,
      limit: limit,
      sid: Map.get(unit, :sid),
      key: Map.get(unit, :key),
      launch_id: unit.launch_id,
      bytes: unit.bytes,
      limit_bytes:
        if(limit == "session", do: unit.limit_bytes, else: state.hosts[host].settings.budget),
      mode: mode,
      at: now
    }

    :ets.insert(table(), {{:kill, unit.id}, kill})

    EventLog.lifecycle(
      state.db,
      "memory_kill_intent",
      host,
      JSON.encode!(%{
        host: host,
        unit: unit.id,
        scope: unit.scope,
        limit: limit,
        bytes: unit.bytes,
        limitBytes: kill.limit_bytes,
        sessionId: kill.sid,
        launchId: unit.launch_id,
        at: now
      })
    )

    record_ended(state, host, kill)

    guard = self()
    killer = state.killer
    target = kill_target(state, unit)

    Task.start(fn ->
      result = killer.(target, state.hosts[host])
      send(guard, {:killed, unit.id, result})
    end)

    %{state | killing: Map.put(state.killing, unit.id, kill)}
  end

  defp kill_target(state, %{scope: "session", record: record} = unit) do
    %{
      scope: "session",
      helper: helper(state),
      pid: record["pid"],
      identity: record["identity"],
      launch_id: record["launchId"],
      unit: Map.get(unit, :unit)
    }
  end

  defp kill_target(_state, %{scope: "adapter", row: row} = unit) do
    %{scope: "adapter", row: row, unit: Map.get(unit, :unit), launch_id: unit.launch_id}
  end

  defp record_ended(state, host, kill) do
    session_key = if kill.sid, do: session_for_sid(state.db, kill.sid)

    EventLog.lifecycle(
      state.db,
      "memory_tree_ended",
      session_key || host,
      JSON.encode!(%{
        host: host,
        scope: kill.scope,
        limit: kill.limit,
        sessionId: kill.sid,
        launchId: kill.launch_id,
        bytes: kill.bytes,
        mode: kill.mode,
        unitEvents: Map.get(kill, :events)
      })
    )
  end

  # `memory.peak` (kernel 5.19+) of an enforced unit, when the kernel has it.
  defp unit_peak(layout, unit) do
    case File.read(Path.join(Cgroup.dir(layout.fs, unit), "memory.peak")) do
      {:ok, text} ->
        case Integer.parse(String.trim(text)) do
          {bytes, _} -> bytes
          :error -> nil
        end

      _ ->
        nil
    end
  end

  # Kernel kills (enforced) and ended session processes (both modes, R11a).
  defp observe_ended(state, host, measured) do
    live = MapSet.new(for unit <- measured.units, unit.scope == "session", do: unit.launch_id)
    table = Map.get(measured, :table)

    Enum.reduce(state.launches, state, fn {launch_id, record}, acc ->
      gone? =
        cond do
          record["placement"] == "enforced" and acc.hosts[host].layout ->
            Cgroup.populated?(acc.hosts[host].layout.fs, record["unit"]) != true

          table ->
            not alive?(table, record)

          true ->
            not MapSet.member?(live, launch_id)
        end

      if gone?, do: session_process_ended(acc, host, record), else: acc
    end)
  end

  defp session_process_ended(state, host, record) do
    layout = state.hosts[host].layout
    id = "session:" <> record["launchId"]

    state =
      if ((record["placement"] == "enforced" and layout) && not Map.has_key?(state.killing, id)) and
           lookup({:kill, id}) == [] do
        case kernel_kill(layout, record["unit"]) do
          nil ->
            state

          limit ->
            # The unit is removed below: keep the kernel's own verdict on it.
            {:ok, counters} = Cgroup.local_events(layout.fs, record["unit"])

            kill = %{
              host: host,
              scope: "session",
              limit: limit,
              sid: record["sessionId"],
              key: nil,
              launch_id: record["launchId"],
              bytes: unit_peak(layout, record["unit"]),
              events: counters,
              limit_bytes:
                if(limit == "session",
                  do: record["sessionLimit"],
                  else: state.hosts[host].settings.budget
                ),
              mode: "enforced",
              at: state.clock.()
            }

            :ets.insert(table(), {{:kill, id}, kill})
            record_ended(state, host, kill)
            state
        end
      else
        state
      end

    # R11a: a session process that ended for any reason other than a close by
    # Tightbeam leaves no stale residency behind.
    forget_residency(state, host, record["sessionId"])

    if layout && record["unit"], do: Cgroup.remove(layout.fs, record["unit"])
    Records.remove(state.base_dir, record["launchId"])
    %{state | launches: Map.delete(state.launches, record["launchId"])}
  end

  defp forget_residency(state, host, sid) do
    for {adapter, entry} <- state.adapters, entry.host == host, MapSet.member?(entry.sids, sid) do
      Task.start(fn -> Tightbeam.Acp.Adapter.forget_session_residency(adapter, sid) end)
    end

    :ok
  end

  # The session unit's local counters say which limit ended it: its own
  # (`oom` ≥ 1) or the budget (`oom_group_kill` ≥ 1 with no local `oom`).
  defp kernel_kill(_layout, nil), do: nil

  defp kernel_kill(layout, unit) do
    case Cgroup.local_events(layout.fs, unit) do
      {:ok, %{"oom_group_kill" => group} = counters} when group >= 1 ->
        if Map.get(counters, "oom", 0) >= 1, do: "session", else: "budget"

      _ ->
        nil
    end
  end

  defp enforced_counters(%{host: host} = match) do
    with %{mode: "enforced", layout: %{} = layout} <- host_view(host) do
      sid = Map.get(match, :harness_session_id)

      session_limit =
        if is_binary(sid), do: kernel_kill(layout, Cgroup.session_unit(layout, sid))

      cond do
        session_limit ->
          %{
            limit: session_limit,
            scope: "session",
            bytes: nil,
            limit_bytes: nil,
            mode: "enforced"
          }

        launch = Map.get(match, :adapter_launch_id) ->
          case Cgroup.local_events(layout.fs, Cgroup.adapter_unit(layout, launch)) do
            {:ok, %{"oom_group_kill" => group}} when group >= 1 ->
              %{limit: "budget", scope: "adapter", bytes: nil, limit_bytes: nil, mode: "enforced"}

            _ ->
              nil
          end

        true ->
          nil
      end
    else
      _ -> nil
    end
  end

  # R17a: after `residentCap` is lowered below the resident count, idle
  # session processes close, one at a time, until the count is back under the
  # cap; working ones finish.
  defp trim_to_cap(state, host) do
    host_state = Map.get(state.hosts, host)

    with %{mode: mode, settings: %{resident_cap: cap}} when mode != "off" and is_integer(cap) <-
           host_state,
         true <- resident_count(state, host, nil) > cap,
         false <- Enum.any?(state.closing, fn {_ref, c} -> c.host == host end),
         {:ok, _ref, state} <- start_close(state, host, "resident_cap") do
      state
    else
      _ -> state
    end
  end

  # R5 and the R2 approach shed idle session processes one at a time.
  defp shed(state, host) do
    host_state = state.hosts[host]

    shedding? =
      (host_state.floor_held and is_number(host_state.available) and
         host_state.available < host_state.settings.floor_release) or host_state.budget_held

    busy_closing? = Enum.any?(state.closing, fn {_ref, c} -> c.host == host end)

    if shedding? and not busy_closing? do
      reason = if host_state.floor_held, do: "memory_floor", else: "memory_budget"

      case start_close(state, host, reason) do
        {:ok, _ref, state} -> state
        :none -> state
      end
    else
      state
    end
  end

  defp expire_kills(state) do
    cutoff = state.clock.() - @kill_retention_ms

    for {{:kill, id}, kill} <- :ets.tab2list(table()),
        kill.at < cutoff,
        do: :ets.delete(table(), {:kill, id})

    for {{:adapter_exit, id}, exit} <- :ets.tab2list(table()),
        exit.at < cutoff,
        do: :ets.delete(table(), {:adapter_exit, id})

    state
  end

  ## R2a

  defp end_adapter_sessions(state, {_harness, _preset, host} = key, launch_id) do
    state = refresh_launches(state)
    host_state = Map.get(state.hosts, host)
    key_launches = launches_of_key(state, key, launch_id)

    victims =
      for {_id, record} <- state.launches,
          record["adapterLaunchId"] in key_launches,
          launch_id == :any_previous or record["adapterLaunchId"] == launch_id,
          do: record

    for record <- victims do
      target = %{
        scope: "session",
        helper: helper(state),
        pid: record["pid"],
        identity: record["identity"],
        launch_id: record["launchId"],
        unit: if(record["placement"] == "enforced", do: record["unit"])
      }

      _ = state.killer.(target, host_state)
    end

    Enum.reduce(victims, state, fn record, acc ->
      forget_residency(acc, host, record["sessionId"])

      if host_state && host_state.layout && record["unit"],
        do: Cgroup.remove(host_state.layout.fs, record["unit"])

      Records.remove(acc.base_dir, record["launchId"])
      %{acc | launches: Map.delete(acc.launches, record["launchId"])}
    end)
    |> remove_adapter_unit(host_state, launch_id)
  end

  # The ended launch, or (`:any_previous`, before a new launch) every launch of
  # the key that has already ended; a running adapter's sessions are its own.
  defp launches_of_key(state, key, which) do
    name = HarnessProcess.adapter_key_name(key)

    state.db
    |> HarnessProcess.list()
    |> Enum.filter(&(&1.adapter_key == name))
    |> Enum.filter(fn row ->
      if which == :any_previous,
        do: row.state not in ["launching", "running", "park_requested"],
        else: true
    end)
    |> Enum.map(& &1.launch_id)
  rescue
    _ -> []
  end

  # Before the unit goes, keep the kernel's verdict on it (R10): a budget kill
  # of the adapter unit is recorded so a turn settled after this still finds it.
  defp remove_adapter_unit(state, %{layout: %{} = layout} = host_state, launch_id)
       when is_binary(launch_id) do
    unit = Cgroup.adapter_unit(layout, launch_id)
    id = "adapter:" <> launch_id

    with {:ok, %{"oom_group_kill" => group}} when group >= 1 <-
           Cgroup.local_events(layout.fs, unit),
         [] <- lookup({:kill, id}),
         %{host: host} <- adapter_row(state, launch_id) do
      kill = %{
        host: host,
        scope: "adapter",
        limit: "budget",
        sid: nil,
        key: parse_key(adapter_row(state, launch_id).adapter_key),
        launch_id: launch_id,
        bytes: nil,
        limit_bytes: host_state.settings.budget,
        mode: "enforced",
        at: state.clock.()
      }

      :ets.insert(table(), {{:kill, id}, kill})
      record_ended(state, host, kill)
    end

    _ = Cgroup.remove(layout.fs, unit)
    state
  end

  defp remove_adapter_unit(state, _host_state, _launch_id), do: state

  defp adapter_row(state, launch_id) do
    Enum.find(HarnessProcess.list(state.db), &(&1.launch_id == launch_id))
  rescue
    _ -> nil
  end

  @doc false
  # The tree kill: `cgroup.kill` on an enforced unit, else the existing
  # `harness-group` kill of the tree's recorded identity, which also finds
  # detached process groups.
  def default_kill(%{unit: unit} = target, %{layout: %{fs: fs}}) when is_binary(unit) do
    case Cgroup.kill(fs, unit) do
      :ok -> :ok
      {:error, _} -> group_kill(target)
    end
  end

  def default_kill(target, _host_state), do: group_kill(target)

  defp group_kill(%{scope: "adapter", row: row}) do
    HarnessProcess.kill_tree(row)
  end

  defp group_kill(%{scope: "session", helper: helper, identity: identity})
       when is_binary(helper) and is_binary(identity) do
    HarnessProcess.kill_session_tree(helper, identity)
  end

  defp group_kill(_target), do: {:error, :no_identity}

  defp helper(%{cli_bin: cli_bin}) when is_binary(cli_bin), do: Path.join(cli_bin, "tightbeam")
  defp helper(_state), do: nil

  ## Read (R12b)

  defp supported_read(state, host) do
    case Map.get(state.hosts, host) do
      nil ->
        nil

      host_state ->
        held =
          Enum.reduce(@details, %{}, fn detail, acc ->
            count =
              Enum.count(state.held, fn {_key, held} ->
                held.host == host and Map.has_key?(held.details, detail)
              end)

            Map.put(acc, detail, count)
          end)

        %{
          host: host,
          mode: host_state.mode,
          notEnforcedReason: if(host_state.mode != "enforced", do: host_state.reason),
          settings: settings_json(host_state.settings),
          explicitSettings: host_state.settings.explicit,
          invalidSettings: host_state.settings.invalid,
          tightbeamTotalBytes: host_state.total,
          hostAvailablePercent:
            host_state.available && Float.round(host_state.available * 1.0, 1),
          residentCount: resident_count(state, host, nil),
          reservedSlot: reserved_slot_read(state, host, host_state),
          oomScoreAdj: oom_read(state, host_state),
          heldTurns: held,
          floorHolds: host_state.floor_held,
          budgetHolds: host_state.budget_held
        }
    end
  end

  # R3b/R7/R12b: the reserve, shown apart from the cap and as its Main's.
  defp reserved_slot_read(state, host, host_state) do
    cap = host_state.settings.resident_cap
    count = resident_count(state, host, nil)
    under = if cap, do: "resident: #{count} of #{cap}", else: "resident: #{count}"

    case Priority.reserved_main(state.db) do
      %{user: user, session_key: key} when is_binary(key) ->
        in_use = reserved_sid(state, host) != nil

        %{
          reservedMain: key,
          owner: user,
          inUse: in_use,
          summary:
            if(in_use,
              do: "#{under}, plus #{user}'s Main in its reserved slot",
              else: "#{under}; reserved slot for #{user}'s Main: empty"
            )
        }

      %{user: user} ->
        %{
          reservedMain: nil,
          owner: user,
          inUse: false,
          summary:
            "#{under}; there is no reserved Main (#{user}'s Main does not exist), so the reserved slot stays empty"
        }

      nil ->
        %{
          reservedMain: nil,
          owner: nil,
          inUse: false,
          summary: "#{under}; there is no reserved Main, so the reserved slot stays empty"
        }
    end
  end

  # R14: the value the gateway (and so every adapter) runs at, and the value
  # session processes are raised to.
  defp oom_read(state, host_state) do
    gateway =
      if host_state.local do
        case File.read(Path.join(state.root, "proc/self/oom_score_adj")) do
          {:ok, text} ->
            case Integer.parse(String.trim(text)) do
              {value, ""} -> value
              _ -> nil
            end

          _ ->
            nil
        end
      end

    %{
      gatewayAndAdapters: gateway,
      sessionProcesses: gateway && min(gateway + host_state.settings.session_oom_score_adj, 1000)
    }
  end

  ## Publication to ETS

  defp publish_all(state) do
    for {host, host_state} <- state.hosts do
      :ets.insert(
        table(),
        {{:host, host},
         %{
           local: host_state.local,
           mode: host_state.mode,
           reason: host_state.reason,
           settings: host_state.settings,
           layout: host_state.layout,
           step: host_state.step,
           dir: Records.dir(state.base_dir),
           available: host_state.available,
           total: host_state.total,
           holds: host_level_reasons(host_state),
           cap_holds:
             Enum.count(state.held, fn {_k, h} ->
               h.host == host and Map.has_key?(h.details, "resident_cap")
             end)
         }}
      )
    end

    state
  end

  defp ensure_table do
    case :ets.whereis(@table) do
      :undefined -> :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
      _ -> @table
    end
  end

  defp table, do: @table

  defp lookup(key) do
    :ets.lookup(@table, key)
  rescue
    ArgumentError -> []
  end
end
