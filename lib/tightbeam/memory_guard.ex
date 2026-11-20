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

  alias Tightbeam.MemoryGuard.{
    Admission,
    Cgroup,
    Episodes,
    RootActions,
    Priority,
    Probe,
    ProcTree,
    Records,
    Settings,
    Unguarded
  }

  @table :tightbeam_memory_guard
  @details ~w(resident_cap memory_floor memory_budget guard_unavailable)
  @kill_retention_ms 15 * 60_000
  @gib 1024 * 1024 * 1024

  ## Public, ETS-backed reads (safe in any process and inside a transaction)

  @doc "The host-capacity details (R7) this contract defines."
  def details, do: @details

  @doc "Whether the guard is running."
  def running?, do: is_pid(Process.whereis(__MODULE__))

  @doc """
  Whether this runtime runs a guard: set when the guard is started (before
  its init, so one that fails to start is still expected) and cleared only on
  its orderly shutdown. An expected guard that is not running is restarting
  or failed, not absent: R2a's launch fence waits for it or fails, never
  passes.
  """
  @spec expect(boolean()) :: :ok
  def expect(expected?), do: :persistent_term.put({__MODULE__, :expected}, expected? == true)

  defp expected?, do: :persistent_term.get({__MODULE__, :expected}, false)

  # The fence's guard: running, back within the wait, or not configured.
  defp fence_guard do
    cond do
      running?() -> :running
      not expected?() -> :not_configured
      await_restart(System.monotonic_time(:millisecond) + restart_wait_ms()) -> :running
      true -> :unavailable
    end
  end

  defp await_restart(deadline) do
    cond do
      running?() ->
        true

      System.monotonic_time(:millisecond) >= deadline ->
        false

      true ->
        Process.sleep(50)
        await_restart(deadline)
    end
  end

  defp restart_wait_ms,
    do: Application.get_env(:tightbeam, :memory_guard_restart_wait_ms, 5_000)

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
  (R6a). Empty when no guard is configured; an expected guard that is not
  running (restarting) stands as `memory_guard_unavailable` on its own host,
  so a hook deferred on it runs once the guard is back.
  """
  @spec host_reasons(String.t()) :: [String.t()]
  def host_reasons(host) do
    case host_view(host) do
      %{holds: holds} ->
        holds

      nil ->
        if expected?() and host == Placement.local_host_name(),
          do: ["memory_guard_unavailable"],
          else: []
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
  def memory_kill(match),
    do:
      memory_kill(
        match,
        System.monotonic_time(:millisecond) +
          Application.get_env(:tightbeam, :memory_guard_attribution_wait_ms, 15_000)
      )

  # Only a kill confirmed to have ended its tree counts (R10). A kill still
  # being carried out when a turn settles is waited for, briefly: settlement
  # stays well inside R9's 30 s, and a kill that fails is never a memory kill.
  defp memory_kill(%{host: host} = match, deadline) do
    since = Map.get(match, :since, 0)

    recorded =
      for {{:kill, _id}, kill} <- :ets.tab2list(table()),
          kill.host == host,
          kill.at >= since,
          (kill.scope == "session" and kill.sid == Map.get(match, :harness_session_id)) or
            (kill.scope == "adapter" and kill.key == Map.get(match, :adapter_key)),
          do: kill

    # v1.13 FS6: `memory_limit` exactly when the intent is recorded (R10a)
    # or the kernel attributes it (R10), and the kill was sent before the
    # tree's end was observed. Whether the kill was confirmed is not part of
    # the test. An intent not yet sent is waited for, inside R9's 30 s.
    attributed =
      recorded
      |> Enum.filter(&(Map.get(&1, :confirmed, true) or Map.has_key?(&1, :sent_at)))
      |> Enum.reject(&Map.get(&1, :ended_before_send, false))

    unsent =
      Enum.filter(recorded, fn kill ->
        not Map.get(kill, :confirmed, true) and not Map.has_key?(kill, :sent_at) and
          not Map.get(kill, :ended_before_send, false)
      end)

    case {Enum.sort_by(attributed, & &1.at), unsent} do
      {[kill | _], _} ->
        Map.take(kill, [:limit, :scope, :bytes, :limit_bytes, :mode])

      {[], [_ | _]} ->
        if System.monotonic_time(:millisecond) < deadline do
          Process.sleep(50)
          memory_kill(match, deadline)
        end

      {[], []} ->
        enforced_counters(match)
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

  @doc """
  A re-admission hook was deferred (R6a): the sampler retries deferred hooks
  each second until none is pending, so a hook runs once the last standing
  reason of any kind clears (a memory release, a park release, a fallback
  outcome).
  """
  @spec note_deferred() :: :ok
  def note_deferred do
    :ets.insert(table(), {:deferred_pending, true})
    :ok
  rescue
    ArgumentError -> :ok
  end

  defp deferred_pending? do
    match?([{:deferred_pending, true}], lookup(:deferred_pending))
  end

  @doc false
  @spec note_adapter_exit(String.t() | nil, integer()) :: :ok
  def note_adapter_exit(nil, _status), do: :ok

  def note_adapter_exit(launch_id, status) do
    low? =
      case Enum.find(:ets.tab2list(table()), &match?({{:host, _}, %{local: true}}, &1)) do
        {_, %{available: available, settings: %{floor_hold: hold}}} when is_number(available) ->
          available < hold

        # FS7 (H3): host memory that cannot be read is recorded as unknown,
        # never a guessed value.
        _ ->
          "unknown"
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
  adapter's own unit (R12c). The step is installed in every mode of the
  gateway's own host: under `off` or `count-only` it execs the harness
  untouched (it reads the mode at each launch), so a later change to
  `watched` or `enforced` reaches the sessions of adapters already running
  (R17: applied without a restart). Empty for a remote host.

  An expected guard with no view of the gateway's own host (restarting) is
  `{:error, :memory_guard_unavailable}`: a launch without the step would
  leave its session processes outside custody (R2a), so it is refused.
  """
  @spec launch_env(tuple(), String.t(), keyword(), DB.server()) ::
          [{String.t(), String.t()}] | {:error, :memory_guard_unavailable}
  def launch_env({_harness, _preset, host} = key, launch_id, opts, db \\ DB) do
    if is_nil(host_view(host)) and expected?() and is_nil(Keyword.get(opts, :process_ssh)) and
         host == Placement.local_host_name(),
       do: {:error, :memory_guard_unavailable},
       else: view_env(key, launch_id, opts, db)
  end

  defp view_env({harness, _preset, host}, launch_id, opts, db) do
    with %{local: true, mode: mode} = view <- host_view(host),
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

  def start_link(opts) do
    expect(true)
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def child_spec(opts),
    do: %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}, restart: :permanent}

  @doc """
  Admission for the next queued turn of `session_key` (R3, R5, R2, R6):
  `:ok`, or `{:held, details}` when the turn needs a launch the host cannot
  take now. A held turn stays `queued`; the guard nudges its lane when it can
  run. The call may wait for an idle session process to close first.
  """
  @spec admit(String.t(), DB.server()) :: :ok | :no_turn | {:held, [String.t()]}
  def admit(session_key, db \\ DB) do
    # v1.13 FS1: a guard that is not running, or does not answer, holds every
    # turn that needs a launch (`guard_unavailable`); there is no time-out
    # admission. Only a runtime with no guard configured admits unguarded.
    case fence_guard() do
      :running -> guarded_admit(session_key, db)
      :not_configured -> :ok
      :unavailable -> Unguarded.admit(db, session_key)
    end
  end

  defp guarded_admit(session_key, db) do
    GenServer.call(
      __MODULE__,
      {:admit, session_key},
      Application.get_env(:tightbeam, :memory_guard_admit_timeout_ms, 120_000)
    )
  catch
    :exit, _ -> Unguarded.admit(db, session_key)
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
  @spec adapter_ended(tuple(), String.t() | nil) :: :ok | {:error, term()}
  def adapter_ended(key, launch_id) do
    case fence_guard() do
      :running -> GenServer.call(__MODULE__, {:adapter_ended, key, launch_id}, call_timeout())
      :not_configured -> :ok
      :unavailable -> {:error, {:memory_guard_unavailable, :not_running}}
    end
  catch
    :exit, reason -> {:error, {:memory_guard_unavailable, reason}}
  end

  @doc """
  R2a backstop before a launch of `key`: no session tree of an earlier launch
  survives. `{:error, _}` refuses the launch: a tree could not be shown to have
  ended, or the guard could not answer. Without a guard (not configured) there
  is nothing it launched.
  """
  @spec ensure_no_orphans(tuple()) :: :ok | {:error, term()}
  def ensure_no_orphans(key) do
    case fence_guard() do
      :running -> GenServer.call(__MODULE__, {:ensure_no_orphans, key}, call_timeout())
      :not_configured -> :ok
      :unavailable -> {:error, {:memory_guard_unavailable, :not_running}}
    end
  catch
    :exit, reason -> {:error, {:memory_guard_unavailable, reason}}
  end

  defp call_timeout, do: Application.get_env(:tightbeam, :memory_guard_call_timeout_ms, 60_000)

  @doc "A host's settings changed (R17): re-determine its mode and apply them."
  @spec settings_changed(String.t()) :: :ok | {:error, term()}
  def settings_changed(host) do
    case fence_guard() do
      :running -> GenServer.call(__MODULE__, {:settings_changed, host}, call_timeout())
      :not_configured -> :ok
      # Stored, not applied: a down guard applies nothing (FS1, M-V2).
      :unavailable -> {:error, {:memory_guard_unavailable, :not_running}}
    end
  catch
    :exit, reason -> {:error, {:memory_guard_unavailable, reason}}
  end

  @doc """
  The host-capacity reasons that would hold `session_key`'s next turn now,
  for the held-state read (R7): `[%{detail, host, since, condition}]`.
  """
  @spec hold_reasons(String.t(), DB.server()) :: [map()]
  def hold_reasons(session_key, db \\ DB) do
    if running?(),
      do: GenServer.call(__MODULE__, {:hold_reasons, session_key}, 10_000),
      else: Unguarded.hold_reasons(db, session_key)
  catch
    # A guard that does not answer: its own hold is the one on record (FS1).
    :exit, _ -> Unguarded.hold_reasons(db, session_key)
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
    # Orderly shutdown runs terminate/2, which clears the expectation.
    Process.flag(:trap_exit, true)
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
      # R4/FS5 (K3, K8): the adapter's own close-if-idle, atomic with its
      # observation of the session.
      killer: Keyword.get(opts, :killer, &default_kill/2),
      # SIGKILL for the parent-chain fallback; tests with a fake /proc inject one.
      signaller: Keyword.get(opts, :signaller, &default_signal/1),
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
      announced: MapSet.new(),
      # The boot identity, for the launch-record inventory's per-boot
      # initialization (FS4 scope): nil when it cannot be read.
      boot: read_boot(root),
      inventory_generation: nil,
      # Tightbeam's own inventory (launch records, harness-process table)
      # cannot be read: launches are held `guard_unavailable` (FS1, FS4 scope).
      inventory_error: nil,
      # What this gateway run has already recorded once (FS4, R12a).
      recorded: MapSet.new(),
      # FS5: closes acknowledged while the session process lives: still
      # resident and counted under R3, and retried. {host, sid} => entry.
      lingering: %{},
      # FS5: closes that failed go after every other candidate and are
      # retried on a later decision.
      close_failed: MapSet.new(),
      # FS7: markers not yet delivered (key => marker), records of effects
      # that already happened but could not be written yet, and unit removals
      # that failed; all retried each sample.
      pending_markers: %{},
      pending_alerts: %{},
      pending_records: [],
      pending_removals: MapSet.new(),
      # Sessions whose hold record failed: nudged again so they re-ask.
      renudge: MapSet.new(),
      # FS9: since when the guard's own launch step or records have held
      # launches, and per key since when a replacement adapter has been
      # refused for custody; an episode opens after 15 minutes unbroken.
      guard_stuck_since: nil,
      custody_refused: %{},
      owner_alert: Keyword.get(opts, :owner_alert, &default_owner_alert/2),
      # FS9: who must own a root action record, and the root-path check.
      root_uid: Keyword.get(opts, :root_uid, 0),
      finding: Keyword.get(opts, :finding, fn -> Tightbeam.MemoryGuard.RootPath.finding() end),
      # Test seam (matrix K7): runs between choosing a close candidate and the
      # conditional `closing` transaction.
      before_close_commit: Keyword.get(opts, :before_close_commit, fn _session_key -> :ok end),
      # Test seam (matrix D4, A5): runs in the kill task before the send.
      before_kill_send: Keyword.get(opts, :before_kill_send, fn _target -> :ok end),
      close_confirm_ms: Keyword.get(opts, :close_confirm_ms, 5_000)
    }

    state = state |> determine_all() |> publish_all()
    # Deferrals recorded before a restart are picked up by the first samples.
    note_deferred()
    # v1.13 FS1: the guard answers again, so every `guard_unavailable` hold is
    # released once init has returned (a nudged lane asks this guard).
    send(self(), :release_unguarded)
    # FS9: a start on a new boot identity ends every episode (a reboot ends
    # every process).
    send(self(), :reboot_check)

    if state.sample_ms != :manual, do: Process.send_after(self(), :tick, state.sample_ms)
    {:ok, state}
  end

  @impl true
  def handle_call({:admit, session_key}, from, state) do
    case safe_admission(state, session_key) do
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
    {reply, state} = end_adapter_sessions(state, key, launch_id)
    {:reply, reply, publish_all(state)}
  end

  def handle_call({:ensure_no_orphans, key}, _from, state) do
    {reply, state} = end_adapter_sessions(state, key, :any_previous)

    state =
      case reply do
        :ok -> custody_cleared(state, key)
        {:error, _} -> custody_refused(state, key)
      end

    {:reply, reply, state}
  end

  def handle_call({:settings_changed, host}, _from, state) do
    state = state |> determine(host) |> publish_all() |> trim_to_cap(host) |> release_check(host)

    case state.hosts[host].transition_error do
      nil -> {:reply, :ok, state}
      error -> {:reply, {:error, {:not_applied, error}}, state}
    end
  end

  # Reads never crash the guard: a read that cannot be completed says so.
  def handle_call({:hold_reasons, session_key}, _from, state) do
    reasons =
      try do
        evaluate_reasons(state, session_key)
      rescue
        _ -> Unguarded.hold_reasons(state.db, session_key)
      end

    {:reply, reasons, state}
  end

  def handle_call({:read, host}, _from, state) do
    read =
      try do
        supported_read(state, host)
      rescue
        error -> %{host: host, mode: "unknown", error: Exception.message(error)}
      end

    {:reply, read, state}
  end

  def handle_call(:tick, _from, state) do
    state = sample(%{state | unclosable: MapSet.new()})
    run_deferred(state)
    release_step_holds(state)
    state = retry_bookkeeping(state)
    state = stuck(state)
    {:reply, :ok, state}
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
    run_deferred(state)
    release_step_holds(state)
    state = retry_bookkeeping(state)
    state = stuck(state)
    Process.send_after(self(), :tick, state.sample_ms)
    {:noreply, state}
  end

  def handle_info(:reboot_check, state) do
    if is_binary(state.boot) do
      for %{"boot" => boot, "episodeId" => id} <- Episodes.active(state.db),
          is_binary(boot) and boot != state.boot,
          do: Episodes.finish(state.db, id, "reboot")
    end

    {:noreply, state}
  rescue
    _ -> {:noreply, state}
  end

  def handle_info(:release_unguarded, state) do
    for {session_key, host} <- Unguarded.held_sessions(state.db) do
      Unguarded.release(state.db, session_key, host, "guard_answers")
      nudge(state, session_key)
    end

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

  # R1/R2 in watched mode: the kill is published as an ended tree, and counts
  # for settlement, only once the tree is shown gone. A failed kill is
  # recorded and retried by the next sample, which still sees it over its limit.
  def handle_info({:killed, id, result}, state) do
    {kill, killing} = Map.pop(state.killing, id)
    state = %{state | killing: killing}

    case {kill, result} do
      {nil, _} ->
        {:noreply, state}

      {kill, :ok} ->
        :ets.insert(table(), {{:kill, id}, Map.put(kill, :confirmed, true)})
        record_ended(state, kill.host, kill)
        {:noreply, publish_all(state)}

      {_kill, {:error, :ended_before_send}} ->
        # FS6: the tree ended before this guard's kill was sent: not a memory
        # kill. The record stays, marked, so settlement says harness_exited.
        {:noreply, state}

      {kill, {:error, reason}} ->
        # The kill was sent (FS6 attributes it), but the tree was not shown
        # gone: recorded, and the next sample retries while it is over its limit.
        EventLog.lifecycle(
          state.db,
          "memory_kill_failed",
          kill.host,
          JSON.encode!(%{
            host: kill.host,
            unit: id,
            scope: kill.scope,
            limit: kill.limit,
            sessionId: kill.sid,
            launchId: kill.launch_id,
            error: inspect(reason)
          })
        )

        {:noreply, state}
    end
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(reason, _state) do
    if reason in [:normal, :shutdown] or match?({:shutdown, _}, reason), do: expect(false)
    :ok
  end

  defp read_boot(root) do
    case File.read(Path.join(root, "proc/sys/kernel/random/boot_id")) do
      {:ok, text} -> String.trim(text)
      {:error, _} -> nil
    end
  end

  ## Modes and settings

  defp determine_all(state) do
    hosts = Map.keys(Placement.hosts(state.base_dir, state.db))
    Enum.reduce(Enum.uniq([state.local_host | hosts]), state, &determine(&2, &1))
  end

  defp determine(state, host) do
    local? = host == state.local_host
    previous = Map.get(state.hosts, host)

    # FS7 (F4): stored settings that cannot be read keep the last effective
    # settings, and the read says so; never defaults silently.
    {stored, settings_gap} =
      try do
        {Settings.stored(state.db, host), nil}
      rescue
        error ->
          {nil,
           "the stored memory settings cannot be read (#{Exception.message(error)}); " <>
             if(previous,
               do: "the last effective settings stay in use",
               else: "the defaults are in use"
             )}
      end

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

    settings =
      cond do
        stored != nil -> Settings.effective(stored, probe.mem_total)
        previous != nil -> previous.settings
        true -> Settings.effective(%{}, probe.mem_total)
      end

    previous_layout = previous && previous.layout

    # A transition is effective only once the kernel's state matches it (R12,
    # R17). `lift` is a layout whose limits must come off; `transition` says
    # what did not take, so the change is reported as not applied and the
    # sampler retries it.
    {mode, reason, layout, lift, transition} =
      cond do
        settings.mode == "off" ->
          {"off", "an admin turned memory limits off for this host", nil, previous_layout, nil}

        probe.mode == :enforced ->
          enter_enforced(state, previous, probe, settings)

        probe.mode == :watched ->
          {"watched", probe.reason, nil, previous_layout, nil}

        true ->
          {"count-only", probe.reason, nil, previous_layout, nil}
      end

    # Leaving `enforced` lifts the kernel's limits on the units that remain
    # (processes stay where they are). Until they are lifted the host does not
    # read as the requested mode: the guard watches every tree (the kernel's
    # remaining limits are the same numbers), and the layout is kept so the
    # next try can lift them.
    {mode, reason, layout, transition} =
      case lift && Cgroup.relax(lift) do
        {:error, error} ->
          gap =
            "the kernel's earlier memory limits could not all be lifted (#{error}); " <>
              "still in force: the budget group's memory.max#{in_force_budget(previous)}, " <>
              "swap 0, and each session unit's own memory.max; they act alongside the guard's " <>
              "own checks, retried every sample"

          gap = if mode == "watched", do: gap, else: "#{mode} is not yet in effect: " <> gap

          {"watched", Enum.join(Enum.reject([reason, gap], &is_nil/1), "; "), lift,
           transition || gap}

        _ ->
          {mode, reason, layout, transition}
      end

    # FS3 (F3): a budget the kernel did not take is not the effective one; the
    # read shows the budget that acts (R12b).
    settings =
      if mode == "enforced" and is_binary(transition) and previous != nil and
           layout != nil and layout == previous.layout,
         do: %{settings | budget: previous.settings.budget},
         else: settings

    step =
      if local? do
        case Records.install_step(state.base_dir, state.cli_bin) do
          {:ok, link} ->
            link

          {:error, error} ->
            Logger.warning("memory guard: session launch step unavailable: #{error}")
            {:unavailable, error}
        end
      end

    published =
      if local? do
        Records.publish_config(state.base_dir, %{
          mode: mode,
          fs: if(mode == "enforced" and layout, do: layout.fs),
          harness: if(mode == "enforced" and layout, do: layout.harness),
          sessionLimit: settings.session_limit,
          oomRaise: 100
        })
      end

    # Anything that keeps this mode from being whole is said on the read and
    # in the mode record (R12a, M-V2), never only logged.
    gaps =
      Enum.reject(
        [
          settings_gap,
          (match?({:unavailable, _}, step) and mode in ["watched", "enforced"]) &&
            "session processes are not limited one by one: the launch step is unavailable (#{elem(step, 1)})",
          match?({:error, _}, published) &&
            "the launch step's settings could not be written: #{inspect(elem(published, 1))}"
        ],
        &(&1 in [nil, false])
      )

    reason = Enum.join(Enum.reject([reason | gaps], &is_nil/1), "; ")
    reason = if reason == "", do: nil, else: reason

    host_state = %{
      local: local?,
      probe: probe,
      mode: mode,
      reason: reason,
      settings: settings,
      layout: layout,
      step: step,
      # The step is in place only when it is installed and its configuration
      # was published (FS1 A3, FS2).
      step_ready: is_binary(step) and published == :ok,
      available: previous && previous.available,
      floor_held: (previous && previous.floor_held) || false,
      floor_since: previous && previous.floor_since,
      total: previous && previous.total,
      budget_held: (previous && previous.budget_held) || false,
      budget_since: previous && previous.budget_since,
      # v1.13 FS4: host readings that failed, each disabling only the guard
      # that needs it: %{reading => %{disables: [..], since: ms}}.
      unavailable: (previous && previous.unavailable) || %{},
      transition_error: transition
    }

    changed? =
      is_nil(previous) or previous.mode != mode or previous.reason != reason or
        previous.settings != settings or previous.transition_error != transition

    # FS7 (F7): a mode change and its record are one step. When the record
    # cannot be written the change is not established: the gateway's own host
    # reads `watched` (every tree sampled; FS3's reading of an unsettled
    # kernel state), and the change is retried every sample.
    host_state =
      if changed? do
        try do
          EventLog.lifecycle(
            state.db,
            "memory_guard_mode",
            host,
            JSON.encode!(%{
              host: host,
              mode: mode,
              reason: reason,
              # Not nil while the requested change is not yet in force (FS3); a
              # down guard's admission reads the mode in force from this (FS1).
              transition: transition,
              settings: settings_json(settings),
              invalid: settings.invalid
            })
          )

          host_state
        rescue
          error ->
            gap =
              "the change of memory limits mode could not be recorded (#{Exception.message(error)}); retried every sample"

            %{
              host_state
              | mode: if(local? and mode in ["enforced", "off"], do: "watched", else: mode),
                reason: Enum.join(Enum.reject([host_state.reason, gap], &is_nil/1), "; "),
                transition_error: host_state.transition_error || gap
            }
        end
      else
        host_state
      end

    %{state | hosts: Map.put(state.hosts, host, host_state)}
  end

  # `{mode, reason, layout, lift, transition}` for a host that can enforce.
  defp enter_enforced(state, previous, probe, settings) do
    existing =
      previous && previous.mode == "enforced" && is_nil(previous.transition_error) &&
        previous.layout

    if existing do
      case Cgroup.set_budget(existing, settings.budget) do
        :ok ->
          {"enforced", nil, existing, nil, nil}

        {:error, error} ->
          gap =
            "the new budget is not yet in effect (#{error}); the earlier budget still acts, retried every sample"

          {"enforced", gap, existing, nil, gap}
      end
    else
      previous_layout = previous && previous.layout

      with {:ok, layout} <- Cgroup.setup(state.fs, probe.cgroup, settings.budget) do
        with {:ok, limits} <- session_limits(state),
             :ok <- Cgroup.restore_units(layout, limits) do
          {"enforced", nil, layout, nil, nil}
        else
          {:error, error} ->
            # Enforced without every unit's own limit would leave a session
            # unlimited while the read says enforced (R12a): back out to watched
            # and retry.
            gap = "the session limits could not all be restored (#{error}); retried every sample"

            {"watched",
             "per-agent memory limits are checked every second, not enforced by the kernel: " <>
               gap, nil, layout, gap}
        end
      else
        {:error, error} ->
          {"watched",
           "per-agent memory limits are checked every second, not enforced by the kernel: " <>
             error, nil, previous_layout, nil}
      end
    end
  end

  # The sessionLimit each recorded session process was launched with (R17a).
  defp session_limits(state) do
    # B4: limits restored from a lost inventory would be no limits at all.
    with {:ok, state} <- ensure_inventory(state),
         {:ok, records} <- Records.read_all(state.base_dir) do
      limits =
        for {_id, record} <- records,
            is_binary(record["unit"]),
            into: %{},
            do: {record["unit"], record["sessionLimit"]}

      {:ok, limits}
    end
  end

  defp in_force_budget(%{settings: %{budget: budget}}) when is_integer(budget),
    do: " (#{gib(budget)})"

  defp in_force_budget(_previous), do: ""

  defp settings_json(settings) do
    %{
      mode: settings.mode,
      budget: settings.budget,
      sessionLimit: settings.session_limit,
      residentCap: settings.resident_cap,
      floorHold: settings.floor_hold,
      floorRelease: settings.floor_release,
      memTotal: settings.mem_total
    }
  end

  ## Admission

  # FS1 (matrix L1–L5): a read the decision needs that fails means the guard
  # cannot answer the admission check: the turn is held `guard_unavailable`,
  # never admitted, never failed; recorded once, and its lane asks again.
  defp safe_admission(state, session_key) do
    admission(state, session_key)
  rescue
    error ->
      message = Exception.message(error)

      state =
        once(state, {:admission_unreadable, session_key}, fn ->
          record(
            state,
            "memory_guard_admission_unreadable",
            session_key,
            JSON.encode!(%{error: message})
          )
        end)

      {:held, ["guard_unavailable"], %{state | renudge: MapSet.put(state.renudge, session_key)}}
  end

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

    closing_ref = closing_ref(state, session)

    cond do
      # R4 (K6, K7): a session whose close has been decided waits for it, then
      # starts a fresh process; it never runs on a process being closed.
      closing_ref != nil ->
        {:closing, closing_ref, state}

      launch == :none ->
        state =
          state
          |> resume_if_held(session.session_key)
          |> mark_busy(session.session_key, session.host)

        {:ok, state}

      true ->
        decide_launch(state, session, host_state, seq, launch, reserved?)
    end
  end

  defp closing_ref(state, session) do
    Enum.find_value(state.closing, fn {ref, closing} ->
      if closing.session_key == session.session_key and closing.host == session.host, do: ref
    end)
  end

  defp decide_launch(state, session, host_state, seq, launch, reserved?) do
    host_reasons = host_level_reasons(host_state)

    # R3b: the reserved Main takes its reserved slot; R3 never holds it. The
    # floor and the budget still do.
    {cap_reason, state} =
      if reserved? and match?({:session, _}, launch),
        do: {nil, state},
        else: cap_decision(state, session, host_state, launch, seq, host_reasons)

    {custody_reason, state} = custody_reason(state, session)

    own_reason =
      step_reason(host_state, launch) || inventory_reason(state) ||
        step_hold_reason(state, session)

    # FS9 guard override: the held launches are admitted without the guard's
    # own step or records, and the risk stays shown until the guard answers.
    own_reason =
      if own_reason && guard_overridden?(state, session.host) do
        for %{"kind" => "guard", "episodeId" => id} <- Episodes.active(state.db, session.host),
            do: Episodes.applied(state.db, id)

        nil
      else
        own_reason
      end

    step_reason = own_reason || custody_reason

    cond do
      match?({:closing, _}, cap_reason) ->
        {:closing, elem(cap_reason, 1), state}

      host_reasons != [] or cap_reason != nil or step_reason != nil ->
        details = host_reasons ++ List.wrap(step_reason) ++ List.wrap(cap_reason)
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
              {:none, state} -> {"resident_cap", state}
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
    lingering = for {{^host, sid}, _entry} <- state.lingering, do: sid

    state.adapters
    |> Map.values()
    |> Enum.filter(&(&1.host == host and Harness.session_processes?(harness_module(&1.key))))
    |> Enum.flat_map(&MapSet.to_list(&1.sids))
    |> Kernel.++(lingering)
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
      {:ok, []} -> nil
      # L2: a queue that cannot be read is not an empty one.
      {:error, error} -> raise "the session's queued turns cannot be read: #{inspect(error)}"
    end
  end

  ## Holds (R6, R6a, R7)

  defp hold(state, session, seq, details) do
    now = state.clock.()

    previous =
      Map.get(state.held, session.session_key, %{details: %{}, host: session.host, seq: seq})

    # FS7 (I3): a hold and its record are one step. A detail whose record
    # cannot be written is not established; the turn stays unclaimed and the
    # lane is nudged to ask again.
    recorded =
      for detail <- details, not Map.has_key?(previous.details, detail) do
        {detail,
         record(
           state,
           "memory_guard_hold",
           session.session_key,
           JSON.encode!(%{
             host: session.host,
             reasonClass: "host_capacity",
             detail: detail,
             since: now,
             condition: condition(state, session.host, detail)
           })
         )}
      end

    failed = for {detail, {:error, _}} <- recorded, do: detail

    new_details =
      for detail <- details, detail not in failed, into: %{} do
        {detail, Map.get(previous.details, detail, now)}
      end

    state =
      if failed == [],
        do: state,
        else: %{state | renudge: MapSet.put(state.renudge, session.session_key)}

    held = %{host: session.host, seq: seq, details: new_details}

    state =
      if new_details == %{},
        do: %{state | held: Map.delete(state.held, session.session_key)},
        else: %{state | held: Map.put(state.held, session.session_key, held)}

    # R7: a user-originated turn that becomes held gets one plain-words
    # marker in its own conversation, once per hold.
    if previous.details == %{} and
         Priority.user_originated_pending?(state.db, session.session_key),
       do: waiting_marker(state, session, hd(details), now),
       else: state
  end

  defp waiting_marker(state, session, detail, since) do
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

        "guard_unavailable" ->
          "Waiting for Tightbeam to be able to start agent processes on #{host} safely: " <>
            "the memory guard's launch step is not ready. " <> line
      end

    post_marker(state, %{
      key: "waiting:#{session.session_key}:#{since}",
      kind: "memory_guard_waiting",
      session_key: session.session_key,
      detail: %{host: host, detail: detail, placeInLine: place},
      message: message
    })
  end

  # R4 / R7 markers (FS7, matrix I2): delivered at most once, under an
  # idempotency key carried in the marker's own record; one that could not be
  # posted is recorded and retried each sample until it is.
  defp post_marker(state, marker) do
    if marker_posted?(state.db, marker) do
      %{state | pending_markers: Map.delete(state.pending_markers, marker.key)}
    else
      try do
        EventLog.notice(
          state.db,
          marker.kind,
          marker.session_key,
          JSON.encode!(Map.put(marker.detail, :markerKey, marker.key)),
          audience: {:session, marker.session_key},
          message: marker.message,
          attention: :normal,
          conn_registry: state.conn_registry
        )

        %{state | pending_markers: Map.delete(state.pending_markers, marker.key)}
      rescue
        error -> marker_pending(state, marker, Exception.message(error))
      catch
        :exit, reason -> marker_pending(state, marker, inspect(reason))
      end
    end
  end

  defp marker_posted?(db, marker) do
    case DB.query(
           db,
           """
           SELECT 1 FROM lifecycle_events
           WHERE kind=?1 AND subject=?2 AND json_extract(detail,'$.markerKey')=?3 LIMIT 1
           """,
           [marker.kind, marker.session_key, marker.key]
         ) do
      {:ok, [[1]]} -> true
      _ -> false
    end
  end

  defp marker_pending(state, marker, error) do
    state =
      if Map.has_key?(state.pending_markers, marker.key),
        do: state,
        else: tap(state, &marker_failed(&1, marker.session_key, marker.kind, error))

    %{state | pending_markers: Map.put(state.pending_markers, marker.key, marker)}
  end

  # FS7: retried each sample.
  defp retry_bookkeeping(state) do
    state =
      Enum.reduce(Map.values(state.pending_markers), state, &post_marker(&2, &1))

    state = Enum.reduce(Map.values(state.pending_alerts), state, &notify_stuck(&2, &1))

    {records, failed} =
      Enum.split_with(state.pending_records, fn {kind, subject, detail} ->
        record(state, kind, subject, detail) == :ok
      end)

    _ = records
    state = %{state | pending_records: failed}

    state =
      Enum.reduce(state.pending_removals, state, fn {fs, unit} = removal, acc ->
        case Cgroup.remove(fs, unit) do
          :ok -> %{acc | pending_removals: MapSet.delete(acc.pending_removals, removal)}
          {:error, _} -> acc
        end
      end)

    for session_key <- state.renudge, do: nudge(state, session_key)
    state = %{state | renudge: MapSet.new()}
    renudge_ready(state)
  end

  # R6 / [SPIRIT] (matrix M1, M3): a held turn is never stranded by a lost
  # nudge. Each sample nudges again every held session that no reason holds
  # now, and every re-admitted turn still queued (its handoff may not have
  # reached the lane). A lane that is nudged needlessly re-asks and is held.
  defp renudge_ready(state) do
    for {session_key, _held} <- state.held,
        evaluate_reasons(state, session_key) == [],
        Admission.other_reasons(state.db, session_key) == [],
        do: nudge(state, session_key)

    for session_key <- Admission.readmitted_queued(state.db), do: nudge(state, session_key)
    state
  end

  # A nudge that fails is not the guard's failure: the next sample retries it.
  defp nudge(state, session_key) do
    state.nudge.(session_key)
  rescue
    error ->
      Logger.warning("memory guard: nudge of #{session_key} failed: #{Exception.message(error)}")
  catch
    :exit, reason ->
      Logger.warning("memory guard: nudge of #{session_key} failed: #{inspect(reason)}")
  end

  # A record that is a state change's own step: `:ok` or `{:error, message}`.
  defp record(state, kind, subject, detail) do
    EventLog.lifecycle(state.db, kind, subject, detail)
  rescue
    error -> {:error, Exception.message(error)}
  catch
    :exit, reason -> {:error, inspect(reason)}
  end

  # An effect that already happened outside the database: its record is kept
  # and retried until it is written, never dropped (FS7, matrix I3).
  defp record_effect(state, kind, subject, detail) do
    case record(state, kind, subject, detail) do
      :ok ->
        state

      {:error, _} ->
        %{state | pending_records: state.pending_records ++ [{kind, subject, detail}]}
    end
  end

  # FS7 (C10): a unit that cannot be removed is recorded and retried; never
  # evidence that a tree ended.
  defp remove_unit(state, fs, unit) do
    case Cgroup.remove(fs, unit) do
      :ok ->
        state

      {:error, error} ->
        state =
          once(state, {:unit_remove_failed, unit}, fn ->
            record(
              state,
              "memory_guard_unit_remove_failed",
              unit,
              JSON.encode!(%{unit: unit, error: error})
            )
          end)

        %{state | pending_removals: MapSet.put(state.pending_removals, {fs, unit})}
    end
  end

  defp marker_failed(state, session_key, kind, error) do
    Logger.warning("memory guard: #{kind} marker not posted for #{session_key}: #{error}")

    EventLog.lifecycle(
      state.db,
      "memory_guard_marker_failed",
      session_key,
      JSON.encode!(%{marker: kind, error: error})
    )
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
      do: nudge(state, reserved)

    state
    |> waiters(host, reserved)
    |> Enum.each(fn {key, _place} -> nudge(state, key) end)

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
          List.wrap(
            step_reason(host_state, launch) || inventory_reason(state) ||
              step_hold_reason(state, session) || custody_held(state, session)
          ) ++
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

  # v1.13 FS1 A3 / FS2: a session process started without the launch step
  # would have no launch record, no per-tree limit, no attribution and no
  # +100, outside custody; it does not start. `off` uses no step.
  defp step_reason(%{local: true, mode: mode, step_ready: false}, {:session, _})
       when mode != "off",
       do: "guard_unavailable"

  defp step_reason(_host_state, _launch), do: nil

  ## FS9: stuck episodes

  # Each sample: retry the ends of refused custody, track how long each
  # condition has held, open an episode after 15 minutes unbroken, and end
  # episodes whose condition cleared.
  defp stuck(state) do
    now = state.clock.()

    state
    |> retry_custody(now)
    |> guard_condition(now)
    |> root_actions(now)
  rescue
    error ->
      Logger.warning("memory guard: stuck-episode pass failed: #{Exception.message(error)}")
      state
  end

  defp retry_custody(state, now) do
    Enum.reduce(state.custody_refused, state, fn {key, %{since: since}}, acc ->
      case end_adapter_sessions(acc, key, :any_previous) do
        {:ok, acc} ->
          custody_cleared(acc, key)

        {{:error, _}, acc} ->
          if now - since >= Episodes.stuck_ms(),
            do: open_episode(acc, custody_episode(acc, key, since)),
            else: acc
      end
    end)
  end

  defp custody_episode(state, {_harness, _preset, host} = key, since) do
    trees =
      case launches_of_key(state, key, :any_previous) do
        {:ok, ended} ->
          for {_id, r} <- state.launches, r["adapterLaunchId"] in ended do
            %{
              launchId: r["launchId"],
              pid: r["pid"],
              start: r["start"],
              unit: if(r["placement"] == "enforced", do: r["unit"])
            }
          end

        {:error, _} ->
          []
      end

    %{
      host: host,
      kind: "custody",
      key: HarnessProcess.adapter_key_name(key),
      trees: trees,
      since: since,
      boot: state.boot,
      base: state.base_dir,
      why: "#{length(trees)} agent processes could not be confirmed stopped"
    }
  end

  # The refusal cleared. An episode ends only when every tree it names is
  # shown gone; one whose fence was lifted by an override stays open, its
  # orphans shown (FS9), until custody_ends_on_proof sees them gone.
  defp custody_cleared(state, key) do
    %{state | custody_refused: Map.delete(state.custody_refused, key)}
  end

  # The guard's own launch step or records hold launches (FS1); the guard is
  # running here, so the guard-down case is the watcher's.
  defp guard_condition(state, now) do
    host = state.local_host
    host_state = Map.get(state.hosts, host)

    cause =
      cond do
        is_nil(host_state) or host_state.mode == "off" ->
          nil

        state.inventory_error ->
          "Tightbeam's own records cannot be read: #{state.inventory_error}"

        not host_state.step_ready ->
          "the memory guard's launch step is not in place"

        true ->
          nil
      end

    cond do
      cause && is_nil(state.guard_stuck_since) ->
        %{state | guard_stuck_since: now}

      cause && now - state.guard_stuck_since >= Episodes.stuck_ms() ->
        open_episode(state, %{
          host: host,
          kind: "guard",
          since: state.guard_stuck_since,
          boot: state.boot,
          base: state.base_dir,
          why: cause
        })

      cause ->
        state

      true ->
        for %{"kind" => "guard", "episodeId" => id} <- Episodes.active(state.db, host),
            do: Episodes.finish(state.db, id, "the memory guard answers")

        %{state | guard_stuck_since: nil}
    end
  end

  defp open_episode(state, attrs) do
    case Episodes.open(state.db, attrs) do
      {:opened, episode} -> notify_stuck(state, episode)
      _ -> state
    end
  end

  # FS9: exactly one owner alert and one Main notice per episode, retried
  # until delivered (Episodes.notify is idempotent).
  defp notify_stuck(state, episode) do
    case Episodes.notify(state.db, episode, state.owner_alert, conn_registry: state.conn_registry) do
      :ok ->
        %{state | pending_alerts: Map.delete(state.pending_alerts, episode["episodeId"])}

      {:error, _reason} ->
        %{state | pending_alerts: Map.put(state.pending_alerts, episode["episodeId"], episode)}
    end
  end

  defp default_owner_alert(episode, message) do
    module = Tightbeam.OwnerAlerts

    if Code.ensure_loaded?(module) and function_exported?(module, :memory_guard_stuck, 2),
      do: apply(module, :memory_guard_stuck, [episode, message]),
      else: :owner_alerts_route_absent
  end

  # Root actions and recovery outcomes (FS9 Steps 1 and 2, B4).
  defp root_actions(state, now) do
    host = state.local_host

    if Map.has_key?(state.hosts, host) do
      RootActions.intake(state.db, state.base_dir, host,
        root_uid: state.root_uid,
        finding: state.finding
      )

      host_state = state.hosts[host]

      RootActions.custody_outcomes(
        state.db,
        host,
        fn tree -> tree_shown_gone?(state, host_state, tree) end,
        fn tree -> tree_state(state, tree) end,
        now
      )

      # The guard is running, so it answers.
      RootActions.guard_outcomes(state.db, host, true, now, now)
      custody_ends_on_proof(state, host_state, host)
      Episodes.publish(state.db, state.base_dir, host)
    end

    state
  end

  defp tree_shown_gone?(state, host_state, tree) do
    gone?(state, host_state, %{
      scope: "session",
      pid: tree["pid"],
      start: tree["start"],
      unit: tree["unit"],
      members: []
    })
  end

  defp tree_state(state, %{"pid" => pid}) when is_integer(pid) do
    case ProcTree.read(Path.join(state.root, "proc"), pid) do
      {:ok, %{state: process_state}} -> process_state
      :error -> if ProcTree.unreadable?(state.root, pid), do: "unreadable", else: "gone"
    end
  end

  defp tree_state(_state, _tree), do: "unknown"

  # A custody episode ends when every tree it names is shown gone (FS9).
  defp custody_ends_on_proof(state, host_state, host) do
    for %{"kind" => "custody", "episodeId" => id, "trees" => trees} <-
          Episodes.active(state.db, host),
        Enum.all?(trees, &tree_shown_gone?(state, host_state, &1)),
        do: Episodes.finish(state.db, id, "every named tree is shown gone")
  end

  # FS9 "What an override does", custody: R2a's fence is lifted for the
  # named trees of an accepted override only (they stay shown as orphans).
  defp overridden_trees(state, {_harness, _preset, host} = key) do
    name = HarnessProcess.adapter_key_name(key)

    for %{"kind" => "custody", "key" => ^name, "episodeId" => id, "trees" => trees} <-
          Episodes.active(state.db, host),
        Episodes.override(state.db, id) != nil,
        tree <- trees,
        into: %{},
        do: {tree["launchId"], id}
  rescue
    _ -> %{}
  end

  # FS9 "What an override does", guard: held launches are admitted without
  # the guard's own launch step or records.
  defp guard_overridden?(state, host) do
    Enum.any?(Episodes.active(state.db, host), fn episode ->
      episode["kind"] == "guard" and Episodes.override(state.db, episode["episodeId"]) != nil
    end)
  rescue
    _ -> false
  end

  # R2a / FS1 (A2): a launch that needs a new adapter for a key waits while a
  # recorded tree of an ended adapter of that key is not shown gone; the guard
  # keeps retrying the end each sample (FS9 bounds the wait).
  defp custody_reason(state, session) do
    key = {Harness.parse!(session.harness).id(), "shared", session.host}

    cond do
      Enum.any?(state.adapters, fn {_pid, entry} -> entry.key == key end) ->
        {nil, state}

      Map.has_key?(state.custody_refused, key) ->
        {"guard_unavailable", state}

      # Only a check here: the ends themselves run on the guard's tick.
      custody_unresolved?(state, key) ->
        {"guard_unavailable", custody_refused(state, key)}

      true ->
        {nil, state}
    end
  end

  # Read-only: the custody hold of a session's key, for the held-state read.
  defp custody_held(state, session) do
    key = {Harness.parse!(session.harness).id(), "shared", session.host}

    if Map.has_key?(state.custody_refused, key) and
         not Enum.any?(state.adapters, fn {_pid, entry} -> entry.key == key end),
       do: "guard_unavailable"
  end

  defp custody_unresolved?(state, key) do
    case launches_of_key(state, key, :any_previous) do
      {:ok, ended} ->
        case Records.read_all(state.base_dir) do
          {:ok, records} -> Enum.any?(records, fn {_id, r} -> r["adapterLaunchId"] in ended end)
          {:error, _} -> true
        end

      {:error, _} ->
        true
    end
  end

  defp custody_refused(state, key) do
    if Map.has_key?(state.custody_refused, key),
      do: state,
      else: put_in(state.custody_refused[key], %{since: state.clock.()})
  end

  # FS2: the step refused this session's launch twice; it waits until the
  # step's prerequisites are healthy again.
  defp step_hold_reason(state, session) do
    if Admission.step_held?(state.db, session.session_key), do: "guard_unavailable"
  end

  # FS2: once everything the step needs is in place, every step-refusal hold
  # is released and its lane nudged.
  defp release_step_holds(state) do
    case Admission.step_held_sessions(state.db) do
      [] ->
        :ok

      held ->
        with %{step_ready: true} <- Map.get(state.hosts, state.local_host),
             :ok <- Records.step_prerequisites(state.base_dir, state.root) do
          for session_key <- held do
            EventLog.lifecycle(
              state.db,
              "memory_guard_step_ready",
              session_key,
              JSON.encode!(%{host: state.local_host, detail: "guard_unavailable"})
            )

            nudge(state, session_key)
          end
        end
    end

    :ok
  end

  # FS4 scope: a launch is decided on Tightbeam's own inventories, read at the
  # decision; while either cannot be read the launch is held (FS1).
  defp inventory_reason(state) do
    if state.local_host in Map.keys(state.hosts) do
      case inventory(state, state.local_host) do
        {:ok, _adapters, _state} -> nil
        {:error, _error, _state} -> "guard_unavailable"
      end
    end
  end

  defp cap_full?(state, session, host_state) do
    case host_state.settings.resident_cap do
      nil ->
        false

      cap ->
        resident_count(state, session.host, session.session_key) >= cap and
          elem(idle_candidates(state, session.host, "resident_cap"), 0) == []
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

      "guard_unavailable" ->
        "starts when Tightbeam's memory guard on #{host} can place new agent processes again " <>
          "(its launch step and its own records are ready); an admin can also set the host's " <>
          "memory limits off"
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
  # R4 / §1: a candidate is idle only when every part of the proof reads and
  # says idle (matrix K1, K2, K4); a part that cannot be read is not idle, and
  # that is recorded once per run.
  defp idle_candidates(state, host, reason) do
    closing = MapSet.new(Map.values(state.closing), &{&1.host, &1.sid})
    reserved = if reason == "resident_cap", do: reserved_sid(state, host)

    resident =
      for {adapter, entry} <- state.adapters,
          entry.host == host,
          Harness.session_processes?(harness_module(entry.key)),
          sid <- entry.sids,
          do: {adapter, sid}

    lingering = for {{^host, sid}, entry} <- state.lingering, do: {entry.adapter, sid}

    candidates =
      for {adapter, sid} <- Enum.uniq(resident ++ lingering),
          not MapSet.member?(closing, {host, sid}),
          not MapSet.member?(state.unclosable, {host, sid}),
          sid != reserved do
        {adapter, sid, idle_proof(state, sid)}
      end

    state =
      Enum.reduce(candidates, state, fn
        {_adapter, sid, {:unproven, why}}, acc -> idle_unproven(acc, host, sid, why)
        _candidate, acc -> acc
      end)

    ready =
      for {adapter, sid, {:idle, session_key, rank}} <- candidates do
        {{MapSet.member?(state.close_failed, {host, sid}), rank},
         Map.get(state.last_used, {host, sid}, 0), adapter, sid, session_key}
      end

    {Enum.sort(ready), state}
  end

  # {:idle, session_key, close_rank} | :busy | {:unproven, why}
  defp idle_proof(state, sid) do
    with {:ok, session_key} <- session_for_sid(state.db, sid),
         false <- Map.has_key?(state.busy, session_key),
         false <- Map.has_key?(state.reservations, session_key),
         {:ok, false} <- turn_pending(state.db, session_key),
         {:ok, rank} <- close_rank(state, session_key) do
      {:idle, session_key, rank}
    else
      true -> :busy
      {:ok, true} -> :busy
      {:error, why} -> {:unproven, why}
    end
  end

  defp idle_unproven(state, host, sid, why) do
    once(state, {:idle_unproven, host, sid, why}, fn ->
      EventLog.lifecycle(
        state.db,
        "memory_guard_idle_unproven",
        host,
        JSON.encode!(%{host: host, sessionId: sid, why: why})
      )
    end)
  end

  defp close_rank(state, session_key) do
    case Org.get(state.db, session_key) do
      nil -> {:error, "the session cannot be read"}
      session -> {:ok, 2 - Priority.rank(Priority.class(state.db, session))}
    end
  rescue
    error -> {:error, "the session's priority cannot be read: #{Exception.message(error)}"}
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
      {:ok, [[key]]} -> {:ok, key}
      {:ok, []} -> {:error, "no session for the harness session"}
      {:error, error} -> {:error, "the session pointer cannot be read: #{inspect(error)}"}
    end
  rescue
    error -> {:error, "the session pointer cannot be read: #{Exception.message(error)}"}
  end

  defp turn_pending(db, session_key) do
    case DB.query(
           db,
           "SELECT 1 FROM turns WHERE sessionKey=?1 AND status IN ('queued','running') LIMIT 1",
           [session_key]
         ) do
      {:ok, [[1]]} -> {:ok, true}
      {:ok, []} -> {:ok, false}
      {:error, error} -> {:error, "the session's turns cannot be read: #{inspect(error)}"}
    end
  rescue
    error -> {:error, "the session's turns cannot be read: #{Exception.message(error)}"}
  end

  # Start closing the least recently used idle session process. Returns :none
  # when no session process is idle.
  #
  # R4 serialization (matrix K6–K8): the close is issued only after one
  # database transaction sets the session's `closing` mark on the condition
  # that no turn of the session is queued or running; every enqueue or claim
  # commits before or after it. Admission is serialized in this process, so a
  # turn arriving after the mark waits for the close. The adapter then closes
  # only if idle by its own observation, in the callback that also orders
  # every prompt it sends.
  defp start_close(state, host, reason) do
    {candidates, state} = idle_candidates(state, host, reason)
    try_close(state, host, reason, candidates)
  end

  defp try_close(state, _host, _reason, []), do: {:none, state}

  defp try_close(state, host, reason, [{_rank, _used, adapter, sid, session_key} | rest]) do
    state.before_close_commit.(session_key)

    case closing_mark(state, host, sid, session_key, reason) do
      :ok ->
        guard = self()
        ref = make_ref()
        closer = state.closer
        idle_check = state.idle_check
        confirm = fn -> close_shown_complete(state, sid) end

        Task.start(fn ->
          result =
            case idle_check.(adapter, sid) do
              :idle ->
                case closer.(adapter, sid, reason) do
                  :ok -> confirm.()
                  other -> other
                end

              other ->
                {:error, {:not_idle, other}}
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

      {:not_idle, _why} ->
        try_close(state, host, reason, rest)
    end
  end

  # The conditional `closing` transaction (K1, K6, K7).
  defp closing_mark(state, host, sid, session_key, reason) do
    DB.transaction(state.db, fn txn ->
      pending =
        DB.Txn.q(
          txn,
          "SELECT 1 FROM turns WHERE sessionKey=?1 AND status IN ('queued','running') LIMIT 1",
          [session_key]
        )

      if pending == [] do
        EventLog.lifecycle_in_txn(
          txn,
          "memory_guard_closing",
          session_key,
          JSON.encode!(%{host: host, sessionId: sid, reason: reason})
        )

        :ok
      else
        {:not_idle, "a turn of the session is queued or running"}
      end
    end)
    |> case do
      {:ok, result} -> result
      {:error, error} -> {:not_idle, "the closing transaction failed: #{inspect(error)}"}
    end
  end

  # FS5 / K5: a close is complete only when the session process is shown
  # gone (its recorded process and, enforced, its unit).
  defp close_shown_complete(state, sid) do
    records =
      case Records.read_all(state.base_dir) do
        {:ok, launches} -> launches |> Map.values() |> Enum.filter(&(&1["sessionId"] == sid))
        {:error, _} -> []
      end

    case records do
      [] ->
        {:error, {:close_unconfirmed, "no readable launch record for the session process"}}

      records ->
        record = Enum.max_by(records, &(&1["launchedAt"] || 0))

        target = %{
          scope: "session",
          pid: record["pid"],
          start: record["start"],
          unit: if(record["placement"] == "enforced", do: record["unit"]),
          members: []
        }

        host_state = Map.get(state.hosts, state.local_host)

        case await_gone(state, host_state, target, state.close_confirm_ms) do
          :ok -> :ok
          :alive -> {:error, {:close_unconfirmed, "the session process is still running"}}
        end
    end
  end

  defp add_waiter(state, ref, session_key, from) do
    update_in(state.closing[ref].waiters, &(&1 ++ [{session_key, from}]))
  end

  defp finish_close(state, closing, result) do
    state =
      case result do
        :ok ->
          # v1.6 R4's residual: without async-task updates an idle close also
          # ends a background shell task the session left running; the close
          # says so, and the session is told once (AS4).
          residual? = not Tightbeam.Acp.Adapter.async_tasks_observed?()

          # The close is shown complete (FS5): its event is retried until
          # written (FS7, I3), and its marker delivered at most once (I2).
          state =
            record_effect(
              state,
              "memory_guard_idle_closed",
              closing.session_key || closing.sid,
              JSON.encode!(
                Map.merge(
                  %{host: closing.host, sessionId: closing.sid, reason: closing.reason},
                  if(residual?,
                    do: %{
                      residual:
                        "any background shell task this session had left running was ended"
                    },
                    else: %{}
                  )
                )
              )
            )

          state =
            if residual? and is_binary(closing.session_key),
              do: residual_marker(state, closing, state.clock.()),
              else: state

          # The close cleared the adapter's residency; reflect it now rather
          # than waiting for the adapter's own residency report.
          adapters =
            Map.update(state.adapters, closing.adapter, nil, fn entry ->
              %{entry | sids: MapSet.delete(entry.sids, closing.sid)}
            end)
            |> Enum.reject(fn {_adapter, entry} -> is_nil(entry) end)
            |> Map.new()

          %{
            state
            | adapters: adapters,
              lingering: Map.delete(state.lingering, {closing.host, closing.sid}),
              close_failed: MapSet.delete(state.close_failed, {closing.host, closing.sid})
          }

        {:error, {:close_unconfirmed, why}} ->
          # FS5: acknowledged while the process lives: it stays resident and
          # counted under R3, with no close event or marker; recorded, and
          # retried on a later decision.
          EventLog.lifecycle(
            state.db,
            "memory_guard_close_failed",
            closing.session_key || closing.sid,
            JSON.encode!(%{
              host: closing.host,
              sessionId: closing.sid,
              reason: closing.reason,
              error: "close acknowledged, but " <> why
            })
          )

          %{
            state
            | lingering:
                Map.put(state.lingering, {closing.host, closing.sid}, %{
                  adapter: closing.adapter,
                  session_key: closing.session_key
                }),
              unclosable: MapSet.put(state.unclosable, {closing.host, closing.sid}),
              close_failed: MapSet.put(state.close_failed, {closing.host, closing.sid})
          }

        result ->
          # Not idle after all (an observed background task, a prompt that
          # arrived) or the close failed: it stays resident and is not picked
          # again until a turn ends or the next sample. A failed close is
          # recorded; finding it busy is not a failure.
          unless match?({:error, {:not_idle, _}}, result) do
            EventLog.lifecycle(
              state.db,
              "memory_guard_close_failed",
              closing.session_key || closing.sid,
              JSON.encode!(%{
                host: closing.host,
                sessionId: closing.sid,
                reason: closing.reason,
                error: inspect(result)
              })
            )
          end

          state = %{state | unclosable: MapSet.put(state.unclosable, {closing.host, closing.sid})}

          if match?({:error, {:not_idle, _}}, result),
            do: state,
            else: %{
              state
              | close_failed: MapSet.put(state.close_failed, {closing.host, closing.sid})
            }
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

  defp residual_marker(state, closing, at) do
    post_marker(state, %{
      key: "closed:#{closing.session_key}:#{closing.sid}:#{at}",
      kind: "memory_guard_idle_closed_marker",
      session_key: closing.session_key,
      detail: %{host: closing.host, reason: closing.reason},
      message:
        "To free memory, Tightbeam closed this session's process while it was idle. Any " <>
          "background shell task you had left running was ended; start it again if you still need it."
    })
  end

  defp default_idle_check(adapter, sid), do: Tightbeam.Acp.Adapter.idle_session?(adapter, sid)

  defp default_close(adapter, sid, _reason) do
    case Tightbeam.Acp.Adapter.close_if_idle(adapter, sid) do
      :ok -> :ok
      {:error, :not_idle} -> {:error, {:not_idle, :busy}}
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
    state = retry_transition(state, host)

    case Map.get(state.hosts, host) do
      %{mode: mode} when mode in ["watched", "enforced"] ->
        state
        |> sample_host(host)
        |> expire_kills()
        |> publish_all()

      _ ->
        state
    end
  end

  # A mode change the kernel did not take is tried again until it does.
  defp retry_transition(state, host) do
    case Map.get(state.hosts, host) do
      %{transition_error: error} when is_binary(error) ->
        state |> determine(host) |> publish_all()

      _ ->
        state
    end
  end

  # v1.13 FS4 scope: the launch records and the harness-process table are
  # Tightbeam's own inventories. While either cannot be read, or the launch
  # records' durably initialized inventory is missing, nothing is counted or
  # ended from them and launches are held `guard_unavailable` (FS1); the R2a
  # fence counts as unresolved (FS8).
  defp refresh_launches(state) do
    with {:ok, state} <- ensure_inventory(state),
         {:ok, launches} <- Records.read_all(state.base_dir) do
      {:ok, %{state | launches: launches}}
    end
  end

  defp ensure_inventory(%{inventory_generation: nil} = state) do
    case Records.init_inventory(state.db, state.base_dir, state.boot) do
      {:ok, generation} -> {:ok, %{state | inventory_generation: generation}}
      {:error, _} = error -> error
    end
  end

  defp ensure_inventory(state) do
    with :ok <- Records.check_inventory(state.base_dir, state.inventory_generation),
         do: {:ok, state}
  end

  defp inventory(state, host) do
    with {:ok, state} <- refresh_launches(state),
         {:ok, adapters} <- local_adapters(state, host) do
      {:ok, adapters, inventory_ok(state)}
    else
      {:error, error} -> {:error, error, state}
      :error -> {:error, "the harness-process table cannot be read", state}
    end
  end

  defp inventory_ok(state), do: %{state | inventory_error: nil}

  defp inventory_failed(state, host, error) do
    state =
      once(state, {:inventory, host}, fn ->
        EventLog.lifecycle(
          state.db,
          "memory_guard_inventory_failed",
          host,
          JSON.encode!(%{host: host, error: error})
        )
      end)

    %{state | inventory_error: error}
  end

  # One record per host per gateway run (FS4, R12a).
  defp once(state, key, record) do
    if MapSet.member?(state.recorded, key) do
      state
    else
      record.()
      %{state | recorded: MapSet.put(state.recorded, key)}
    end
  end

  defp sample_host(state, host) do
    now = state.clock.()
    state = sample_floor(state, host, now)

    case inventory(state, host) do
      {:ok, adapters, state} ->
        measured = measure(state, state.hosts[host], adapters)
        state = apply_measurement(state, host, measured, now)
        state |> shed(host) |> trim_to_cap(host)

      {:error, error, state} ->
        state |> inventory_failed(host, error) |> shed(host)
    end
  end

  # FS4: a runtime `/proc/meminfo` failure disables R5 only, and its
  # `memory_floor` reason counts as clear.
  defp sample_floor(state, host, now) do
    case Probe.available_percent(state.root) do
      {:ok, available} ->
        state = reading_ok(state, host, "meminfo")
        state = put_in(state.hosts[host].available, available)
        floor_transition(state, host, available, now)

      :error ->
        state = reading_failed(state, host, "meminfo", ["R5"])
        state = put_in(state.hosts[host].available, nil)

        if state.hosts[host].floor_held do
          state
          |> put_in([:hosts, host, :floor_held], false)
          |> put_in([:hosts, host, :floor_since], nil)
          |> host_released(host, "memory_floor", %{because: "host memory cannot be read"})
        else
          state
        end
    end
  end

  defp apply_measurement(state, host, measured, now) do
    trees_ok? = measured.trees == :ok
    total_ok? = is_integer(measured.total)

    state =
      if trees_ok?,
        do: reading_ok(state, host, "tree"),
        else: reading_failed(state, host, "tree", ["R1", "R2"])

    state =
      case Map.get(measured, :total_read) do
        nil -> state
        :ok -> reading_ok(state, host, "budget_total")
        :unreadable -> reading_failed(state, host, "budget_total", ["R2 approach"])
      end

    # R2's approach needs the total and, in watched mode, every tree; without
    # them it is unavailable and its hold counts as clear (FS4).
    state =
      if trees_ok? and total_ok?,
        do: budget_transition(state, host, measured.total, now),
        else: clear_budget_hold(state, host)

    state = put_in(state.hosts[host].total, if(total_ok?, do: measured.total))
    state = announce_unplaced(state, host, measured)
    state = announce_unplaced_sessions(state, host)
    state = watched_limits(state, host, measured, state.hosts[host].settings)
    observe_ended(state, host, measured)
  end

  defp clear_budget_hold(state, host) do
    if state.hosts[host].budget_held do
      state
      |> put_in([:hosts, host, :budget_held], false)
      |> put_in([:hosts, host, :budget_since], nil)
      |> host_released(host, "memory_budget", %{
        because: "Tightbeam's memory total cannot be read"
      })
    else
      state
    end
  end

  defp reading_failed(state, host, reading, disables) do
    state =
      once(state, {:reading, host, reading}, fn ->
        EventLog.lifecycle(
          state.db,
          "memory_guard_sampling_failed",
          host,
          JSON.encode!(%{
            host: host,
            mode: state.hosts[host].mode,
            reading: reading,
            disables: disables
          })
        )
      end)

    update_in(state.hosts[host].unavailable, fn unavailable ->
      Map.put_new(unavailable, reading, %{disables: disables, since: state.clock.()})
    end)
  end

  defp reading_ok(state, host, reading),
    do: update_in(state.hosts[host].unavailable, &Map.delete(&1, reading))

  # Per unit: %{id, scope, sid?, key?, launch_id, bytes, limit_bytes, pids?, unit?}.
  # The result also says whether every tree was read (`trees`) and carries the
  # Tightbeam total, or nil when it cannot be read (FS4).
  defp measure(state, host_state, adapters) do
    case host_state.mode do
      "enforced" ->
        measure_enforced(state, host_state, adapters)

      "watched" ->
        case measure_watched(state, adapters, Map.values(state.launches)) do
          {:ok, measured} -> Map.put(measured, :trees, :ok)
          :error -> %{units: [], total: nil, trees: :unreadable, table: nil}
        end
    end
  end

  defp local_adapters(state, host) do
    rows = HarnessProcess.list(state.db)

    adapters =
      for row <- rows,
          row.host == host,
          is_nil(row.ssh),
          row.state == "running",
          is_integer(row.os_pid),
          do: row

    {:ok, adapters}
  rescue
    _ -> :error
  end

  defp measure_watched(state, adapters, launches, exclude \\ nil) do
    with {:ok, table} <- ProcTree.snapshot(state.root),
         :ok <- roots_readable(state, table, adapters, launches),
         # E3: a process of ours that cannot be read may be any tree's member.
         [] <- ProcTree.unreadable_own(state.root, table) do
      measure_trees(table, adapters, launches, exclude)
    else
      _ -> :error
    end
  end

  # A known root missing from the snapshot has either ended or could not be
  # read; only the first is a smaller tree.
  defp roots_readable(state, table, adapters, launches) do
    roots =
      Enum.map(adapters, & &1.os_pid) ++
        for(record <- launches, is_integer(record["pid"]), do: record["pid"])

    if Enum.any?(roots, &(not Map.has_key?(table, &1) and ProcTree.unreadable?(state.root, &1))),
      do: :error,
      else: :ok
  end

  defp measure_trees(table, adapters, launches, exclude) do
    sessions =
      for record <- launches,
          alive?(table, record),
          do: record

    session_trees = ProcTree.trees(table, Enum.map(sessions, & &1["pid"]))

    in_sessions =
      (exclude || sessions)
      |> Enum.filter(&alive?(table, &1))
      |> Enum.map(& &1["pid"])
      |> then(&ProcTree.trees(table, &1))
      |> Map.values()
      |> Enum.reduce(MapSet.new(), &MapSet.union/2)

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
  end

  defp measure_enforced(state, host_state, adapters) do
    layout = host_state.layout

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

    # R12a/R12c: an adapter is enforced only when it is a member of its
    # unit. One that is not (its join failed, or it predates the mode) is
    # sampled and limited as in watched mode, and the gap is recorded.
    {placed, unplaced_adapters} =
      Enum.split_with(
        adapters,
        &in_unit?(state.root, &1.os_pid, Cgroup.adapter_unit(layout, &1.launch_id))
      )

    adapter_units =
      for row <- placed do
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

    # A session tree the kernel could not take (its cgroup failed) is
    # sampled and limited as in watched mode too.
    unplaced = for {_id, r} <- state.launches, r["placement"] != "enforced", do: r

    watched =
      case {unplaced, unplaced_adapters} do
        {[], []} -> {:ok, %{units: []}}
        {records, rows} -> measure_watched(state, rows, records, Map.values(state.launches))
      end

    # FS4: the budget group's total and the unplaced trees are separate host
    # readings. An unplaced tree's memory is outside the budget group's count,
    # so without its read the total is unknown too, never a smaller one.
    {watched_units, trees} =
      case watched do
        {:ok, %{units: units}} -> {units, :ok}
        :error -> {[], :unreadable}
      end

    harness_total = Cgroup.current(layout.fs, layout.harness)

    total =
      case {harness_total, trees} do
        {{:ok, bytes}, :ok} -> bytes + Enum.sum(Enum.map(watched_units, & &1.bytes))
        _ -> nil
      end

    %{
      units: enforced_sessions ++ adapter_units ++ watched_units,
      total: total,
      trees: trees,
      total_read: if(match?({:ok, _}, harness_total), do: :ok, else: :unreadable)
    }
  end

  # Whether a process is a member of `unit`, from its own /proc/<pid>/cgroup.
  defp in_unit?(root, pid, unit) when is_integer(pid) do
    case File.read(Path.join([root, "proc", Integer.to_string(pid), "cgroup"])) do
      {:ok, text} ->
        String.contains?(text, "0::" <> unit <> "\n") or String.trim(text) == "0::" <> unit

      _ ->
        false
    end
  end

  defp in_unit?(_root, _pid, _unit), do: false

  # C3: a unit's own counter is shown unknown (nil) when it cannot be read,
  # never 0; the kernel enforces the unit's limit either way.
  defp unit_bytes(_layout, nil), do: nil

  defp unit_bytes(layout, unit) do
    case Cgroup.current(layout.fs, unit) do
      {:ok, bytes} -> bytes
      :error -> nil
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

    case record(
           state,
           "memory_guard_release",
           host,
           JSON.encode!(
             Map.merge(facts, %{host: host, detail: detail, remaining: remaining_host})
           )
         ) do
      :ok -> released(state, host, detail, remaining_host)
      # FS7: a release and its record are one step; unrecorded, the hold still
      # stands and the next sample tries again.
      {:error, _} -> restore_hold(state, host, detail)
    end
  end

  defp restore_hold(state, host, "memory_floor"),
    do: put_in(state.hosts[host].floor_held, true)

  defp restore_hold(state, host, "memory_budget"),
    do: put_in(state.hosts[host].budget_held, true)

  defp restore_hold(state, _host, _detail), do: state

  defp released(state, host, detail, remaining_host) do
    held_keys = for {key, held} <- state.held, held.host == host, do: key

    for session_key <- held_keys do
      other = Admission.other_reasons(state.db, session_key)
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

    if remaining_host == [], do: run_deferred(state)

    release_check(state, host)
  end

  # Deferred hooks run once nothing stands; the flag keeps the per-second
  # sampler from querying when nothing was ever deferred.
  # Deferred hooks run on every host no memory reason holds; the pending flag
  # clears only when none is left anywhere. Hooks waiting on another reason
  # (a limit-fallback evaluation) are retried each tick, in every mode.
  defp run_deferred(state) do
    if deferred_pending?() do
      for {host, host_state} <- state.hosts,
          host_level_reasons(host_state) == [],
          do: Admission.run_deferred(state.db, host)

      unless Admission.pending?(state.db), do: :ets.insert(table(), {:deferred_pending, false})
    end

    :ok
  end

  # R12a / C8: on an enforced host, a session tree the step could not place in
  # its unit runs watched, and that is recorded once per launch.
  defp announce_unplaced_sessions(state, host) do
    if state.hosts[host].mode == "enforced" do
      Enum.reduce(state.launches, state, fn {launch, record}, acc ->
        if record["placement"] != "enforced" and
             not MapSet.member?(acc.announced, {:unplaced_session, launch}) do
          EventLog.lifecycle(
            acc.db,
            "memory_guard_launch_unplaced",
            host,
            JSON.encode!(%{
              host: host,
              launchId: launch,
              scope: "session",
              sessionId: record["sessionId"],
              error: Enum.join(List.wrap(record["errors"]), "; ")
            })
          )

          %{acc | announced: MapSet.put(acc.announced, {:unplaced_session, launch})}
        else
          acc
        end
      end)
    else
      state
    end
  end

  # R12a: on an enforced host, an adapter outside its unit is recorded once.
  defp announce_unplaced(state, host, measured) do
    if state.hosts[host].mode == "enforced" do
      Enum.reduce(measured.units, state, fn
        %{scope: "adapter", pids: _, launch_id: launch} = unit, acc ->
          if MapSet.member?(acc.announced, {:unplaced, launch}) do
            acc
          else
            EventLog.lifecycle(
              acc.db,
              "memory_guard_launch_unplaced",
              host,
              JSON.encode!(%{
                host: host,
                launchId: launch,
                error:
                  "the adapter is not in its memory unit; it is sampled and limited every second instead",
                unit: unit.id
              })
            )

            %{acc | announced: MapSet.put(acc.announced, {:unplaced, launch})}
          end

        _unit, acc ->
          acc
      end)
    else
      state
    end
  end

  # R1 and R2 in watched mode (and for unplaced trees on an enforced host).
  defp watched_limits(state, host, measured, settings) do
    mode = state.hosts[host].mode
    units = measured.units

    over_session =
      Enum.find(units, fn unit ->
        Map.has_key?(unit, :pids) and unit.scope == "session" and is_integer(unit.limit_bytes) and
          is_integer(unit.bytes) and unit.bytes > unit.limit_bytes and
          not Map.has_key?(state.killing, unit.id)
      end)

    cond do
      over_session != nil ->
        kill_unit(state, host, over_session, "session", mode)

      mode in ["watched", "enforced"] and is_integer(settings.budget) and
        is_integer(measured.total) and measured.total > settings.budget and
          map_size(state.killing) == 0 ->
        # Watched: every unit is the gateway's to end. Enforced: the kernel
        # ends placed units; the gateway ends only the ones it samples (R12a).
        victim =
          units
          |> Enum.filter(&(mode == "watched" or Map.has_key?(&1, :pids)))
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
      at: now,
      confirmed: false
    }

    # R10a: the intent is recorded before the first signal; it becomes a
    # memory kill only once the tree is shown gone (handle_info :killed).
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

    guard = self()
    target = kill_target(state, unit)
    host_state = state.hosts[host]

    send_hook = state.before_kill_send

    Task.start(fn ->
      send_hook.(target)

      # FS6: the kill counts only if it is sent before the tree's end is
      # observed; a tree already gone is not killed by this guard.
      result =
        if root_present?(state, target) do
          :ets.insert(table(), {{:kill, unit.id}, Map.put(kill, :sent_at, state.clock.())})
          end_tree(state, host_state, target)
        else
          :ets.insert(table(), {{:kill, unit.id}, Map.put(kill, :ended_before_send, true)})
          {:error, :ended_before_send}
        end

      send(guard, {:killed, unit.id, result})
    end)

    %{state | killing: Map.put(state.killing, unit.id, kill)}
  end

  defp kill_target(state, %{scope: "session", record: record} = unit) do
    %{
      scope: "session",
      helper: helper(state),
      pid: record["pid"],
      start: record["start"],
      identity: record["identity"],
      launch_id: record["launchId"],
      unit: Map.get(unit, :unit)
    }
  end

  defp kill_target(_state, %{scope: "adapter", row: row} = unit) do
    %{scope: "adapter", row: row, unit: Map.get(unit, :unit), launch_id: unit.launch_id}
  end

  defp record_ended(state, host, kill) do
    session_key =
      with sid when is_binary(sid) <- kill.sid,
           {:ok, key} <- session_for_sid(state.db, sid),
           do: key,
           else: (_ -> nil)

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
    trees_read? = Map.get(measured, :trees, :ok) == :ok

    Enum.reduce(state.launches, state, fn {launch_id, record}, acc ->
      gone? =
        cond do
          record["placement"] == "enforced" and acc.hosts[host].layout ->
            Cgroup.populated?(acc.hosts[host].layout.fs, record["unit"]) in [false, :gone]

          # A leader missing from the snapshot only because its read failed has
          # not ended.
          table ->
            not alive?(table, record) and
              not (is_integer(record["pid"]) and ProcTree.unreadable?(state.root, record["pid"])) and
              (not is_integer(record["pid"]) or
                 ProcTree.group_survivors(table, record["pid"], record["start"]) == [])

          # Trees that could not be read are not trees that ended (FS4).
          not trees_read? ->
            false

          true ->
            not MapSet.member?(live, launch_id)
        end

      if gone?, do: session_process_ended(acc, host, record), else: acc
    end)
  end

  defp session_process_ended(state, host, record) do
    # FS5: a lingering process is gone now; it no longer counts.
    state = %{state | lingering: Map.delete(state.lingering, {host, record["sessionId"]})}

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

    state =
      if layout && record["unit"], do: remove_unit(state, layout.fs, record["unit"]), else: state

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
         false <- Enum.any?(state.closing, fn {_ref, c} -> c.host == host end) do
      case start_close(state, host, "resident_cap") do
        {:ok, _ref, state} -> state
        {:none, state} -> state
      end
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
        {:none, state} -> state
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
    host_state = Map.get(state.hosts, host)

    # Not knowing which launches ended, or which session processes they left,
    # is not "nothing to end".
    with {:ok, state} <- refresh_launches(state) |> custody(),
         {:ok, key_launches} <- launches_of_key(state, key, launch_id) do
      end_launches(state, host, host_state, key_launches, launch_id)
    else
      {:error, _} = error -> {error, state}
    end
  end

  defp custody({:ok, _} = ok), do: ok
  defp custody({:error, error}), do: {:error, {:custody_unreadable, error}}

  defp end_launches(state, host, host_state, key_launches, launch_id) do
    key = key_of_launches(state, key_launches)
    # FS9: the named trees of an accepted custody override no longer fence the
    # key; they stay recorded, shown as orphans with the risk.
    overridden = if key, do: overridden_trees(state, key), else: %{}

    victims =
      for {_id, record} <- state.launches,
          record["adapterLaunchId"] in key_launches,
          launch_id == :any_previous or record["adapterLaunchId"] == launch_id,
          not Map.has_key?(overridden, record["launchId"]),
          do: record

    for id <- Enum.uniq(Map.values(overridden)), do: Episodes.applied(state.db, id)

    results =
      for record <- victims do
        target = %{
          scope: "session",
          helper: helper(state),
          pid: record["pid"],
          start: record["start"],
          identity: record["identity"],
          launch_id: record["launchId"],
          unit: if(record["placement"] == "enforced", do: record["unit"])
        }

        {record, end_tree(state, host_state, target)}
      end

    # Custody is kept for every tree not shown gone: its record stays, so the
    # next attempt (the pre-launch backstop) can end it.
    state =
      Enum.reduce(results, state, fn
        {record, :ok}, acc ->
          forget_residency(acc, host, record["sessionId"])

          acc =
            if host_state && host_state.layout && record["unit"],
              do: remove_unit(acc, host_state.layout.fs, record["unit"]),
              else: acc

          Records.remove(acc.base_dir, record["launchId"])
          %{acc | launches: Map.delete(acc.launches, record["launchId"])}

        {_record, {:error, _}}, acc ->
          acc
      end)

    case for({record, {:error, reason}} <- results, do: {record["launchId"], reason}) do
      [] ->
        {:ok, remove_adapter_unit(state, host_state, launch_id)}

      survivors ->
        EventLog.lifecycle(
          state.db,
          "memory_guard_orphans",
          host,
          JSON.encode!(%{
            host: host,
            adapterLaunchId: if(is_binary(launch_id), do: launch_id),
            survivors:
              Enum.map(survivors, fn {launch, reason} ->
                %{launchId: launch, error: inspect(reason)}
              end)
          })
        )

        {{:error, {:session_trees_survive, Enum.map(survivors, &elem(&1, 0))}}, state}
    end
  end

  # End one tree and show it gone (R1, R2, R2a, M-V7): the killer's own
  # verdict is not enough. A tree is gone when its recorded process (same start
  # time) is no longer running, every process of the tree captured before the
  # kill is gone too, and, in enforced mode, its unit holds nothing. A killer
  # that ran and reported survivors keeps its failure even once those checks
  # pass: it captures escaped descendants this read cannot see. A killer that
  # could not run (for example the identity file is missing) killed nothing;
  # the captured tree is ended by its parent chain instead.
  @helper_not_run [:identity_missing, :identity_malformed, :not_a_group_leader, :no_identity]

  @doc false
  def end_tree(state, host_state, target) do
    target = Map.put(target, :members, capture(state, target))
    first = state.killer.(target, host_state)

    gone =
      case await_gone(state, host_state, target, 5_000) do
        :ok ->
          :ok

        :alive ->
          _ = walk_kill(state, target)
          await_gone(state, host_state, target, 5_000)
      end

    cond do
      gone == :alive -> {:error, {:tree_survives, first}}
      first == :ok -> :ok
      match?({:error, reason} when reason in @helper_not_run, first) -> :ok
      true -> {:error, {:kill_incomplete, first}}
    end
  end

  # The tree's processes with their start times, read before the kill; a read
  # that fails is not an empty tree.
  defp capture(state, target) do
    with {pid, start} when is_integer(pid) <- root_of(target),
         true <- running?(state.root, pid, start),
         {:ok, table} <- ProcTree.snapshot(state.root) do
      for member <- ProcTree.tree(table, pid), do: {member, table[member].start}
    else
      :error -> :unknown
      _ -> []
    end
  end

  defp root_present?(state, target) do
    case root_of(target) do
      {pid, start} -> present?(state.root, pid, start)
      nil -> true
    end
  end

  defp root_of(%{scope: "session", pid: pid, start: start}), do: {pid, start}
  defp root_of(%{scope: "adapter", row: row}), do: {row.os_pid, nil}
  defp root_of(_target), do: nil

  defp await_gone(state, host_state, target, ms) do
    deadline = System.monotonic_time(:millisecond) + ms

    Stream.repeatedly(fn -> gone?(state, host_state, target) end)
    |> Enum.reduce_while(:alive, fn
      true, _ ->
        {:halt, :ok}

      false, _ ->
        if System.monotonic_time(:millisecond) >= deadline do
          {:halt, :alive}
        else
          Process.sleep(50)
          {:cont, :alive}
        end
    end)
  end

  defp gone?(state, host_state, target) do
    unit_empty? =
      case {Map.get(target, :unit), host_state && host_state.layout} do
        # An unreadable unit is not an empty one.
        {unit, %{fs: fs}} when is_binary(unit) -> Cgroup.populated?(fs, unit) in [false, :gone]
        _ -> true
      end

    members_gone? =
      case Map.get(target, :members, []) do
        # Without the tree read, only an emptied unit shows its members gone.
        :unknown -> is_binary(Map.get(target, :unit)) and unit_empty?
        members -> not Enum.any?(members, fn {pid, start} -> present?(state.root, pid, start) end)
      end

    root_gone? =
      case root_of(target) do
        {pid, start} -> not present?(state.root, pid, start)
        nil -> true
      end

    # B2.stale / D1.absent / E2.absent: a session leader that has gone is not
    # its tree; without a unit to show it empty, no process of its group or
    # session may remain (read-only; nothing found this way is signalled).
    group_gone? =
      case {Map.get(target, :unit), target} do
        {unit, _} when is_binary(unit) ->
          true

        {_, %{scope: "session", pid: pid, start: start}} when is_integer(pid) ->
          group_gone?(state, pid, start)

        _ ->
          true
      end

    root_gone? and members_gone? and unit_empty? and group_gone?
  end

  defp group_gone?(state, pid, start) do
    case ProcTree.snapshot(state.root) do
      {:ok, table} -> ProcTree.group_survivors(table, pid, start) == []
      :error -> false
    end
  end

  # Running, or there but unreadable: either way not shown gone.
  defp present?(root, pid, start),
    do: running?(root, pid, start) or (is_integer(pid) and ProcTree.unreadable?(root, pid))

  # A process is running when /proc has it, it is not a zombie, and (when
  # known) its start time is the recorded one: a reused pid is not ours.
  defp running?(root, pid, start) when is_integer(pid) do
    case ProcTree.read(Path.join(root, "proc"), pid) do
      {:ok, %{state: "Z"}} -> false
      {:ok, %{start: ^start}} -> true
      {:ok, _} -> is_nil(start)
      :error -> false
    end
  end

  defp running?(_root, _pid, _start), do: false

  # SIGKILL the captured members still running and whatever the root's tree
  # holds now.
  defp walk_kill(state, target) do
    captured =
      case Map.get(target, :members, []) do
        :unknown -> []
        members -> for {pid, start} <- members, running?(state.root, pid, start), do: pid
      end

    current =
      with {pid, start} when is_integer(pid) <- root_of(target),
           true <- running?(state.root, pid, start),
           {:ok, table} <- ProcTree.snapshot(state.root) do
        MapSet.to_list(ProcTree.tree(table, pid))
      else
        _ -> []
      end

    pids = Enum.uniq(captured ++ current)
    if pids != [], do: state.signaller.(pids)
    :ok
  end

  defp default_signal(pids) do
    System.cmd("kill", ["-KILL" | Enum.map(pids, &Integer.to_string/1)], stderr_to_stdout: true)
    :ok
  end

  # The ended launch, or (`:any_previous`, before a new launch) every launch of
  # the key that has already ended; a running adapter's sessions are its own.
  defp key_of_launches(state, launch_ids) do
    Enum.find_value(HarnessProcess.list(state.db), fn row ->
      if row.launch_id in launch_ids, do: parse_key(row.adapter_key)
    end)
  rescue
    _ -> nil
  end

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
    |> then(&{:ok, &1})
  rescue
    error -> {:error, {:launches_unreadable, Exception.message(error)}}
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

    remove_unit(state, layout.fs, unit)
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
          budgetHolds: host_state.budget_held,
          # FS4: each host reading that failed and the guards it disables, named
          # until a read succeeds; FS1: Tightbeam's own records unreadable.
          unavailable:
            for {reading, %{disables: disables, since: since}} <- host_state.unavailable do
              %{reading: reading, disables: disables, since: since}
            end,
          recordsUnreadable: if(host_state.local, do: state.inventory_error),
          # FS9: open stuck episodes, shown until they end.
          stuckEpisodes: Episodes.read(state.db, host)
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
      sessionProcesses: gateway && min(gateway + 100, 1000)
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
