defmodule Tightbeam.MemoryGuard.Watcher do
  @moduledoc """
  FS9 while the memory guard itself is down (memory limits v1.13 §6.1): the
  guard cannot open its own `guard` episode, so this small process, apart from
  it in the gateway's tree, does what needs no guard:

  - opens a `guard` episode once launches on the host have been held
    `guard_unavailable` (FS1) for 15 minutes without a break, and sends its
    one alert and Main notice (retried until delivered);
  - judges `guard` recovery records root wrote (B4) and their outcome:
    `failed` 5 minutes after the first gateway start that found the record
    (a record written during this run waits for root's restart), if the
    guard has still not answered;
  - publishes the active episodes for the root commands.

  While the guard runs it does nothing: the guard does all of this itself.
  """

  use GenServer
  require Logger

  alias Tightbeam.MemoryGuard
  alias Tightbeam.MemoryGuard.{Episodes, Journal, Publish, RootActions, Unguarded}

  def start_link(opts),
    do: GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))

  @doc "Run one pass now (tests)."
  def tick(server \\ __MODULE__), do: GenServer.call(server, :tick, 60_000)

  @impl true
  def init(opts) do
    state = %{
      db: Keyword.fetch!(opts, :db),
      base_dir: Keyword.fetch!(opts, :base_dir),
      host: Keyword.get(opts, :local_host, Tightbeam.Placement.local_host_name()),
      # This gateway's start: the runtime's, not this process's, so a restart
      # of the watcher alone is not a service restart (FS9 Step 1, B2).
      started: Keyword.get_lazy(opts, :started, &gateway_started/0),
      clock: Keyword.get(opts, :clock, fn -> System.system_time(:millisecond) end),
      interval: Keyword.get(opts, :interval_ms, 30_000),
      guard_running?: Keyword.get(opts, :guard_running?, &MemoryGuard.running?/0),
      owner_alert:
        Keyword.get(opts, :owner_alert, &Tightbeam.OwnerAlerts.memory_guard_stuck_in_txn/2),
      root_uid: Keyword.get(opts, :root_uid, 0),
      finding: Keyword.get(opts, :finding, fn -> Tightbeam.MemoryGuard.RootPath.finding() end),
      root_seen: MapSet.new(),
      # Each episode's alert text, with the root-path finding taken when it
      # was first sent; a retry sends the same text.
      messages: %{}
    }

    if state.interval != :manual, do: Process.send_after(self(), :tick, state.interval)
    {:ok, state}
  end

  defp gateway_started do
    {since_start, _} = :erlang.statistics(:wall_clock)
    System.system_time(:millisecond) - since_start
  end

  @impl true
  def handle_call(:tick, _from, state), do: {:reply, :ok, pass(state)}

  @impl true
  def handle_info(:tick, state) do
    state = pass(state)
    Process.send_after(self(), :tick, state.interval)
    {:noreply, state}
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp pass(state) do
    if state.guard_running?.() do
      state
    else
      now = state.clock.()
      publish_pending(state, now)
      state = state |> open_guard_episode(now) |> nudge_off_holds()

      %{seen: seen, error: error} =
        RootActions.intake(state.db, state.base_dir, state.host,
          root_uid: state.root_uid,
          kinds: ["guard"],
          finding: state.finding,
          seen: state.root_seen
        )

      if error, do: Logger.warning("memory guard watcher: root actions: #{error}")
      state = %{state | root_seen: seen}

      RootActions.guard_outcomes(state.db, state.host, false, state.started, now)

      with {:error, message} <- Episodes.publish(state.db, state.base_dir, state.host),
           do: Logger.warning("memory guard watcher: episodes not published: #{message}")

      # Alerts and notices not yet recorded are retried (idempotent).
      Enum.reduce(Episodes.active(state.db, state.host), state, &notify(&2, &1))
    end
  rescue
    error ->
      Logger.warning("memory guard watcher: #{Exception.message(error)}")
      state
  end

  # D3: while the guard is down, this process owns the step configuration's
  # pending publication (for example `off` brought into force without the
  # guard), at most a page per pass.
  defp publish_pending(state, now) do
    case Journal.page(state.db, state.host, "publish_config", nil, nil, 8) do
      {:ok, effects} ->
        for effect <- effects,
            {:error, error} <- [Publish.resolve_config(state.db, state.base_dir, effect, now)],
            do:
              Logger.warning(
                "memory guard watcher: launch step settings not yet written: #{error}"
              )

      {:error, error} ->
        Logger.warning("memory guard watcher: the effect journal cannot be read: #{error}")
    end
  end

  defp notify(state, episode) do
    id = episode["episodeId"]

    message = fn episode ->
      Map.get_lazy(state.messages, id, fn -> Episodes.message(episode, state.finding.()) end)
    end

    if episode["alert"] != nil and episode["notified"] do
      %{state | messages: Map.delete(state.messages, id)}
    else
      text = message.(episode)

      case Episodes.notify(state.db, episode,
             route: state.owner_alert,
             message: fn _ -> text end
           ) do
        :ok ->
          %{state | messages: Map.delete(state.messages, id)}

        {:error, reason} ->
          Logger.warning("memory guard watcher: episode #{id} alert not sent: #{inspect(reason)}")
          %{state | messages: Map.put(state.messages, id, text)}
      end
    end
  end

  # While `off` is in force with the guard down, the lanes still held from
  # before are admitted when they ask again: a page of 64 is nudged per pass
  # (re-review att_5f6e6736 B4), cycling through the holds from a durable
  # cursor (bounded-continuations design §4).
  defp nudge_off_holds(state) do
    with "off" <- Unguarded.mode_in_force(state.db, state.host),
         {:error, error} <- Unguarded.nudge_pass(state.db, state.host),
         do: Logger.warning("memory guard watcher: held lanes not nudged, retried: #{error}")

    state
  end

  # The oldest `guard_unavailable` hold still open on the host (one indexed
  # row): launches have been held, without a break, since then. Holds that
  # cannot be read open nothing now and are read again on the next pass.
  defp open_guard_episode(state, now) do
    case Unguarded.held_since(state.db, state.host) do
      {:error, reason} ->
        Logger.warning("memory guard watcher: holds cannot be read: #{reason}")
        state

      {:ok, oldest} ->
        with true <- is_integer(oldest),
             true <- now - oldest >= Episodes.stuck_ms(),
             {:opened, episode} <-
               Episodes.open(state.db, %{
                 host: state.host,
                 kind: "guard",
                 since: oldest,
                 base: state.base_dir,
                 why: "the memory guard is not running"
               }) do
          notify(state, episode)
        else
          {:error, reason} ->
            Logger.warning("memory guard watcher: episode not opened, retried: #{reason}")
            state

          _ ->
            state
        end
    end
  end
end
