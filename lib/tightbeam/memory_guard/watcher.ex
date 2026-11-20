defmodule Tightbeam.MemoryGuard.Watcher do
  @moduledoc """
  FS9 while the memory guard itself is down (memory limits v1.13 §6.1): the
  guard cannot open its own `guard` episode, so this small process, apart from
  it in the gateway's tree, does what needs no guard:

  - opens a `guard` episode once launches on the host have been held
    `guard_unavailable` (FS1) for 15 minutes without a break, and sends its
    one alert and Main notice (retried until delivered);
  - judges `guard` recovery records root wrote (B4) and their outcome:
    `failed` 5 minutes after the gateway start that found the record, if the
    guard has still not answered;
  - publishes the active episodes for the root commands.

  While the guard runs it does nothing: the guard does all of this itself.
  """

  use GenServer
  require Logger

  alias Tightbeam.MemoryGuard
  alias Tightbeam.MemoryGuard.{Episodes, RootActions, Unguarded}

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
      started: System.system_time(:millisecond),
      clock: Keyword.get(opts, :clock, fn -> System.system_time(:millisecond) end),
      interval: Keyword.get(opts, :interval_ms, 30_000),
      guard_running?: Keyword.get(opts, :guard_running?, &MemoryGuard.running?/0),
      owner_alert:
        Keyword.get(opts, :owner_alert, fn _episode, _message -> :owner_alerts_route_absent end),
      root_uid: Keyword.get(opts, :root_uid, 0),
      finding: Keyword.get(opts, :finding, fn -> Tightbeam.MemoryGuard.RootPath.finding() end)
    }

    if state.interval != :manual, do: Process.send_after(self(), :tick, state.interval)
    {:ok, state}
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
    unless state.guard_running?.() do
      now = state.clock.()
      open_guard_episode(state, now)

      RootActions.intake(state.db, state.base_dir, state.host,
        root_uid: state.root_uid,
        kinds: ["guard"],
        finding: state.finding
      )

      RootActions.guard_outcomes(state.db, state.host, false, state.started, now)
      Episodes.publish(state.db, state.base_dir, state.host)

      # Alerts and notices not yet delivered are retried (idempotent).
      for episode <- Episodes.active(state.db, state.host),
          do: Episodes.notify(state.db, episode, state.owner_alert)
    end

    state
  rescue
    error ->
      Logger.warning("memory guard watcher: #{Exception.message(error)}")
      state
  end

  # The oldest `guard_unavailable` hold still open on the host: launches have
  # been held, without a break, since then.
  defp open_guard_episode(state, now) do
    since =
      for {session_key, host} <- Unguarded.held_sessions(state.db),
          host == state.host,
          %{since: since} <- [Unguarded.open_hold(state.db, session_key)],
          do: since

    case since do
      [] ->
        :ok

      list ->
        oldest = Enum.min(list)

        if now - oldest >= Episodes.stuck_ms() do
          case Episodes.open(state.db, %{
                 host: state.host,
                 kind: "guard",
                 since: oldest,
                 base: state.base_dir,
                 why: "the memory guard is not running"
               }) do
            {:opened, episode} -> Episodes.notify(state.db, episode, state.owner_alert)
            _ -> :ok
          end
        end
    end
  end
end
