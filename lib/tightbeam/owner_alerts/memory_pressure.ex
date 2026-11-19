defmodule Tightbeam.OwnerAlerts.MemoryPressure do
  @moduledoc """
  Alert kind G1: host memory pressure. The gateway watches its own host and
  tells the alert owner through the owner-alert path when memory runs low. It
  only watches: it stops, throttles or changes nothing.

  Three processes, started in this order:

  - `Marker` is the one writer of the run marker file,
    `memory-pressure-run.json` in the gateway's state directory. It never
    touches the database. Commands are applied in order and a queue of them
    collapses to the latest, so a late update can never bring back a marker
    that was deleted after it.
  - `Recorder` runs every database transaction: the open and close of an
    episode, the restart alert, and lifecycle events.
  - `Sampler` reads `/proc/pressure/memory` and `/proc/meminfo` every 15
    seconds on the monotonic clock while alerts are on, decides runs and
    episodes, and hands every write to the other two. It never waits on the
    database or on Harklight while it samples.

  A pressure run is an unbroken sequence of pressure samples; its marker is
  written at its first sample, so a host that thrashes to a reset still
  leaves the record the next start reports (M6). An episode opens after a run
  of 120 seconds and two samples, or at a pressure sample more than 30 seconds
  late, and closes after 15 continuous minutes of clear samples.
  """

  use Supervisor

  alias Tightbeam.DB.Txn

  @doc """
  Options: `:db`, `:scheduler` (the wake scheduler a filed fact nudges),
  `:state_dir` (the directory holding the gateway's database), and the test
  seams `:host`, `:proc_root`, `:cgroup_root`, `:clock` (monotonic
  milliseconds), `:wall_clock` (wall milliseconds), `:interval` (`:manual`
  samples only on `sample_now/2`), `:os`, `:clock_source`, `:trace` (a pid
  told of every file read and marker write), `:db_hook` and `:marker_hook`,
  and `:owner_alerts` (the delivery process told once the boot is recorded).
  """
  def start_link(opts) do
    name = Keyword.get(opts, :name, __MODULE__)
    Supervisor.start_link(__MODULE__, Keyword.put(opts, :name, name), name: name)
  end

  @impl true
  def init(opts) do
    names = names(Keyword.fetch!(opts, :name))

    Supervisor.init(
      [
        {__MODULE__.Marker, Keyword.put(opts, :name, names.marker)},
        {__MODULE__.Recorder, Keyword.merge(opts, name: names.recorder, sampler: names.sampler)},
        {__MODULE__.Sampler,
         Keyword.merge(opts,
           name: names.sampler,
           recorder: names.recorder,
           marker: names.marker
         )}
      ],
      strategy: :one_for_all
    )
  end

  @doc "The registered names of one instance's processes."
  def names(name \\ __MODULE__) do
    %{
      sampler: Module.concat(name, Sampler),
      recorder: Module.concat(name, Recorder),
      marker: Module.concat(name, Marker)
    }
  end

  @doc """
  After this transaction commits, tell the sampler to read the alert owner
  again: a cleared owner stops it, a new owner starts it afresh (§7.1).
  """
  @spec owner_changed_in_txn(Txn.t()) :: :ok
  def owner_changed_in_txn(%Txn{} = txn),
    do: Txn.handoff(txn, names().recorder, :check_owner)

  @doc """
  Take one sample now, for a sampler started with `interval: :manual`.
  Returns `:disabled` while the sampler is not running, else whether a run
  and an episode stand after the sample.
  """
  def sample_now(name \\ __MODULE__, timeout \\ 5_000),
    do: GenServer.call(names(name).sampler, :sample, timeout)
end

defmodule Tightbeam.OwnerAlerts.MemoryPressure.Probe do
  @moduledoc false
  # V3: the only files read are /proc/pressure/memory, /proc/meminfo,
  # /proc/self/cgroup and cgroupfs memory counters. No process command line,
  # environment or per-process file is ever read.

  defstruct proc_root: "/proc", cgroup_root: "/sys/fs/cgroup", trace: nil

  def new(opts) do
    %__MODULE__{
      proc_root: Keyword.get(opts, :proc_root, "/proc"),
      cgroup_root: Keyword.get(opts, :cgroup_root, "/sys/fs/cgroup"),
      trace: Keyword.get(opts, :trace)
    }
  end

  @doc "One sample, or :error when /proc/meminfo cannot be read."
  def sample(%__MODULE__{} = probe) do
    with {:ok, text} <- read(probe, Path.join(probe.proc_root, "meminfo")),
         {:ok, memory} <- meminfo(text) do
      {avg10, avg60} = psi(probe)
      {:ok, Map.merge(memory, %{"someAvg10" => avg10, "someAvg60" => avg60})}
    else
      _ -> :error
    end
  end

  @doc "M2: P1 (`some avg60` ≥ 10.00) or P2 (low available memory and swap)."
  def pressure?(sample) do
    avg60 = sample["someAvg60"]

    (is_number(avg60) and avg60 >= 10.0) or
      low?(sample, 20, 10)
  end

  @doc "M3: PSI below 5.00 or absent, and memory not below the clear levels."
  def clear?(sample) do
    avg60 = sample["someAvg60"]
    (is_nil(avg60) or avg60 < 5.0) and not low?(sample, 25, 15)
  end

  defp low?(sample, available_pct, swap_pct) do
    sample["memAvailableKiB"] * 100 < available_pct * sample["memTotalKiB"] and
      (sample["swapTotalKiB"] == 0 or
         sample["swapFreeKiB"] * 100 < swap_pct * sample["swapTotalKiB"])
  end

  defp meminfo(text) do
    fields =
      for line <- String.split(text, "\n"),
          [_, key, value] <- [Regex.run(~r/^(\w+):\s+(\d+)\s+kB/, line)],
          into: %{},
          do: {key, String.to_integer(value)}

    case fields do
      %{"MemTotal" => total, "MemAvailable" => available, "SwapTotal" => swap, "SwapFree" => free}
      when total > 0 ->
        {:ok,
         %{
           "memTotalKiB" => total,
           "memAvailableKiB" => available,
           "swapTotalKiB" => swap,
           "swapFreeKiB" => free
         }}

      _ ->
        :error
    end
  end

  # Without /proc/pressure/memory both values are nil and P2 decides alone.
  defp psi(probe) do
    with {:ok, text} <- read(probe, Path.join(probe.proc_root, "pressure/memory")),
         [_, avg10, avg60] <-
           Regex.run(~r/^some avg10=(\d+(?:\.\d+)?) avg60=(\d+(?:\.\d+)?)/m, text) do
      {to_float(avg10), to_float(avg60)}
    else
      _ -> {nil, nil}
    end
  end

  defp to_float(text), do: text |> Float.parse() |> elem(0)

  @doc """
  M9: memory by population from cgroup v2, or nil without it. Each figure is
  the group's `memory.current` plus `memory.swap.current`; when any group has
  no swap counter, every figure is memory only and the result says so.
  Other services are `system.slice` minus this gateway's cgroup (when it sits
  there) and the containers, so no other unit is walked.
  """
  def populations(%__MODULE__{} = probe) do
    with true <- File.exists?(Path.join(probe.cgroup_root, "cgroup.controllers")),
         {:ok, text} <- read(probe, Path.join(probe.proc_root, "self/cgroup")),
         [_, own] <- Regex.run(~r/^0::(\S+)$/m, text) do
      groups(probe, own)
    else
      _ -> nil
    end
  end

  defp groups(probe, own) do
    own_figure = if own != "/", do: figure(probe, own)
    machines = figure(probe, "/machine.slice")

    containers =
      probe |> container_scopes() |> Enum.map(&figure(probe, &1)) |> Enum.reject(&is_nil/1)

    users = figure(probe, "/user.slice")
    system = figure(probe, "/system.slice")
    found = Enum.reject([own_figure, machines, users, system | containers], &is_nil/1)
    swap? = found != [] and Enum.all?(found, &is_integer(&1.swap))

    total = fn
      nil -> nil
      figure -> figure.mem + if(swap?, do: figure.swap, else: 0)
    end

    own_total = total.(own_figure)
    containers_total = if containers != [], do: containers |> Enum.map(total) |> Enum.sum()

    others =
      if system do
        own_share = if String.starts_with?(own, "/system.slice/"), do: own_total || 0, else: 0
        max(total.(system) - own_share - (containers_total || 0), 0)
      end

    listed =
      Enum.reject(
        [
          ["Tightbeam and its agents", own_total],
          ["virtual machines", total.(machines)],
          ["containers", containers_total],
          ["your own programs", total.(users)],
          ["other services", others]
        ],
        fn [_label, bytes] -> is_nil(bytes) end
      )

    if listed != [], do: %{"populations" => listed, "swapAccounted" => swap?}
  end

  defp container_scopes(probe) do
    dir = Path.join(probe.cgroup_root, "system.slice")
    trace(probe, {:memory_pressure_list, dir})

    case File.ls(dir) do
      {:ok, names} ->
        names
        |> Enum.filter(&(String.starts_with?(&1, "docker-") and String.ends_with?(&1, ".scope")))
        |> Enum.sort()
        |> Enum.map(&("/system.slice/" <> &1))

      {:error, _} ->
        []
    end
  end

  defp figure(probe, group) do
    dir = Path.join(probe.cgroup_root, group)

    case counter(probe, Path.join(dir, "memory.current")) do
      {:ok, memory} ->
        swap =
          case counter(probe, Path.join(dir, "memory.swap.current")) do
            {:ok, swap} -> swap
            :error -> nil
          end

        %{mem: memory, swap: swap}

      :error ->
        nil
    end
  end

  defp counter(probe, path) do
    with {:ok, text} <- read(probe, path),
         {value, _rest} <- Integer.parse(String.trim(text)) do
      {:ok, value}
    else
      _ -> :error
    end
  end

  defp read(probe, path) do
    trace(probe, {:memory_pressure_read, path})
    File.read(path)
  end

  defp trace(%{trace: nil}, _event), do: :ok
  defp trace(%{trace: pid}, event), do: send(pid, event)
end

defmodule Tightbeam.OwnerAlerts.MemoryPressure.Marker do
  @moduledoc false
  # A2b: the run marker file. This process is its only writer (F1). Every
  # write is atomic: a temporary file is written and synced, renamed over the
  # marker, and the directory is synced (F2). It never touches the database.

  use GenServer
  require Logger

  @file_name "memory-pressure-run.json"

  def path(state_dir), do: Path.join(state_dir, @file_name)

  def put(server, marker, reason), do: GenServer.cast(server, {:marker, {:put, marker, reason}})
  def delete(server), do: GenServer.cast(server, {:marker, :delete})

  @doc "Return once every command sent before it has been applied."
  def flush(server) do
    GenServer.call(server, :flush, 5_000)
  catch
    :exit, _ -> :ok
  end

  @doc """
  The marker a previous run left, read without the writer: `:none`,
  `{:marker, map}`, or `{:unreadable, marked_at}` for a marker that exists but
  cannot be parsed (marked_at is its modification time, or nil).
  """
  def read(state_dir) do
    path = path(state_dir)

    case File.read(path) do
      {:error, :enoent} ->
        :none

      {:ok, bytes} ->
        case JSON.decode(bytes) do
          {:ok, marker} -> if valid?(marker), do: {:marker, marker}, else: unreadable(path)
          {:error, _} -> unreadable(path)
        end

      {:error, _} ->
        unreadable(path)
    end
  end

  defp unreadable(path) do
    case File.stat(path, time: :posix) do
      {:ok, %{mtime: mtime}} -> {:unreadable, mtime * 1_000}
      {:error, _} -> {:unreadable, nil}
    end
  end

  @sample_counts ~w(memTotalKiB memAvailableKiB swapTotalKiB swapFreeKiB)
  # runEndedAt arrived after the first markers; a marker without it is a run
  # that had not ended.
  @marker_keys ~w(host runStartedAt runEndedAt episodeOpenedAt lastSampleAt lastSample)

  defp valid?(
         %{
           "host" => host,
           "runStartedAt" => started_at,
           "episodeOpenedAt" => opened_at,
           "lastSampleAt" => sampled_at,
           "lastSample" => %{} = sample
         } = marker
       )
       when is_binary(host) and host != "" and is_integer(started_at) and is_integer(sampled_at) do
    Enum.all?(Map.keys(marker), &(&1 in @marker_keys)) and
      (is_nil(opened_at) or is_integer(opened_at)) and
      (is_nil(marker["runEndedAt"]) or is_integer(marker["runEndedAt"])) and
      Enum.all?(@sample_counts, &(is_integer(sample[&1]) and sample[&1] >= 0)) and
      sample["memTotalKiB"] > 0 and
      Enum.all?(~w(someAvg10 someAvg60), &(is_nil(sample[&1]) or is_number(sample[&1])))
  end

  defp valid?(_marker), do: false

  def start_link(opts),
    do: GenServer.start_link(__MODULE__, opts, name: Keyword.fetch!(opts, :name))

  @impl true
  def init(opts) do
    path = path(Keyword.fetch!(opts, :state_dir))
    # A temporary file left by a write that never finished is not the marker.
    _ = File.rm(path <> ".tmp")

    {:ok,
     %{
       path: path,
       hook: Keyword.get(opts, :marker_hook, fn _command -> :ok end),
       trace: Keyword.get(opts, :trace)
     }}
  end

  @impl true
  def handle_cast({:marker, command}, state) do
    apply_command(state, latest(command))
    {:noreply, state}
  end

  @impl true
  def handle_call(:flush, _from, state), do: {:reply, :ok, state}

  # Latest state wins: commands already queued behind this one supersede it.
  defp latest(command) do
    receive do
      {:"$gen_cast", {:marker, next}} -> latest(next)
    after
      0 -> command
    end
  end

  defp apply_command(state, command) do
    result =
      case state.hook.(command) do
        :ok -> write(state.path, command)
        {:error, _} = error -> error
      end

    case result do
      :ok ->
        trace(state, command)

      {:error, reason} ->
        Logger.warning("memory pressure run marker #{action(command)} failed: #{inspect(reason)}")
        if state.trace, do: send(state.trace, {:memory_pressure_marker, :failed, command})
    end
  rescue
    error ->
      Logger.warning(
        "memory pressure run marker #{action(command)} failed: #{Exception.message(error)}"
      )
  end

  defp action({:put, _marker, _reason}), do: "write"
  defp action(:delete), do: "delete"

  defp write(path, {:put, marker, _reason}) do
    tmp = path <> ".tmp"
    File.mkdir_p!(Path.dirname(path))

    with {:ok, file} <- :file.open(String.to_charlist(tmp), [:write, :binary, :raw]),
         :ok <- write_synced(file, JSON.encode!(marker) <> "\n"),
         :ok <- :file.rename(String.to_charlist(tmp), String.to_charlist(path)) do
      sync_dir(Path.dirname(path))
    end
  end

  defp write(path, :delete) do
    case File.rm(path) do
      :ok -> sync_dir(Path.dirname(path))
      {:error, :enoent} -> :ok
      {:error, _} = error -> error
    end
  end

  defp write_synced(file, bytes) do
    result =
      with :ok <- :file.write(file, bytes),
           do: :file.sync(file)

    close = :file.close(file)
    if result == :ok, do: close, else: result
  end

  # The rename (or removal) is durable only once its directory is synced. The
  # marker is already in place when this runs, so a failure here is reported
  # loudly but does not unmake the write.
  defp sync_dir(dir) do
    result =
      with {:ok, handle} <- :file.open(String.to_charlist(dir), [:read, :raw, :directory]) do
        synced = :file.sync(handle)
        :file.close(handle)
        synced
      end

    if result != :ok,
      do: Logger.warning("memory pressure run marker directory sync failed: #{inspect(result)}")

    :ok
  end

  defp trace(%{trace: nil}, _command), do: :ok

  defp trace(%{trace: pid}, {:put, marker, reason}),
    do: send(pid, {:memory_pressure_marker, :put, reason, marker})

  defp trace(%{trace: pid}, :delete), do: send(pid, {:memory_pressure_marker, :delete})
end

defmodule Tightbeam.OwnerAlerts.MemoryPressure.Recorder do
  @moduledoc false
  # Every database write of G1 runs here, off the sampler: the boot restart
  # check (M6), an episode's open (M4) and close (M5), and lifecycle events.
  # All are best effort. A failed open is retried by the sampler while the
  # episode stands; a failed close or owner read is retried here.

  use GenServer
  require Logger

  alias Tightbeam.OwnerAlerts

  @retry_ms 60_000

  def start_link(opts),
    do: GenServer.start_link(__MODULE__, opts, name: Keyword.fetch!(opts, :name))

  @doc """
  M6 at start, then the alert owner. Returns `{:ok, owner}` once the restart
  (if any) is recorded, or `{:error, reason}`.
  """
  def boot(server, found, now) do
    GenServer.call(server, {:boot, found, now}, 60_000)
  catch
    :exit, reason -> {:error, inspect(reason, limit: 10)}
  end

  def open(server, request), do: GenServer.cast(server, {:open, request})
  def close(server, request), do: GenServer.cast(server, {:close, request})
  def lifecycle(server, kind, detail), do: GenServer.cast(server, {:lifecycle, kind, detail})

  @impl true
  def init(opts) do
    {:ok,
     %{
       db: Keyword.get(opts, :db, Tightbeam.DB),
       scheduler: Keyword.get(opts, :scheduler, Tightbeam.WakeScheduler),
       sampler: Keyword.fetch!(opts, :sampler),
       host: Keyword.get_lazy(opts, :host, &Tightbeam.Placement.local_host_name/0),
       hook: Keyword.get(opts, :db_hook, fn _operation -> :ok end)
     }}
  end

  @impl true
  def handle_call({:boot, found, now}, _from, state) do
    reply =
      attempt(fn ->
        state.hook.(:boot)

        if found != :none,
          do: OwnerAlerts.memory_restart(state.db, state.scheduler, state.host, found, now)

        OwnerAlerts.owner(state.db)
      end)

    {:reply, reply, state}
  end

  @impl true
  def handle_cast(:check_owner, state) do
    case attempt(fn ->
           state.hook.(:check_owner)
           OwnerAlerts.owner(state.db)
         end) do
      {:ok, owner} -> GenServer.cast(state.sampler, {:alerts, owner})
      {:error, reason} -> retry(:check_owner, "alert owner read", reason)
    end

    {:noreply, state}
  end

  def handle_cast({:open, request}, state) do
    result =
      case attempt(fn ->
             state.hook.(:open)
             OwnerAlerts.open_memory_episode(state.db, state.scheduler, request)
           end) do
        {:ok, result} ->
          result

        {:error, reason} ->
          Logger.error("memory pressure episode open was not recorded: #{reason}")
          {:error, reason}
      end

    GenServer.cast(state.sampler, {:opened, request.episode_opened_at, result})
    {:noreply, state}
  end

  def handle_cast({:close, request} = message, state) do
    case attempt(fn ->
           state.hook.(:close)
           OwnerAlerts.close_memory_episode(state.db, state.scheduler, request)
         end) do
      {:ok, :closed} -> :ok
      {:error, reason} -> retry(message, "episode close", reason)
    end

    {:noreply, state}
  end

  def handle_cast({:lifecycle, kind, detail}, state) do
    case attempt(fn ->
           state.hook.(:lifecycle)
           OwnerAlerts.memory_lifecycle(state.db, kind, state.host, detail)
         end) do
      {:ok, :ok} -> :ok
      {:error, reason} -> Logger.warning("memory pressure #{kind} was not recorded: #{reason}")
    end

    {:noreply, state}
  end

  @impl true
  def handle_info({:retry, message}, state), do: handle_cast(message, state)

  defp retry(message, what, reason) do
    Logger.error("memory pressure #{what} failed; retrying: #{reason}")
    Process.send_after(self(), {:retry, message}, @retry_ms)
  end

  defp attempt(fun) do
    {:ok, fun.()}
  rescue
    error -> {:error, Exception.message(error)}
  catch
    kind, reason -> {:error, inspect({kind, reason}, limit: 10)}
  end
end

defmodule Tightbeam.OwnerAlerts.MemoryPressure.Sampler do
  @moduledoc false
  # M1–M5: samples every 15 s on the monotonic clock while alerts are on, and
  # decides runs and episodes. Every write is handed to the marker writer or
  # the recorder; nothing here waits on the database or Harklight once
  # sampling has started. Run and open decisions use the monotonic clock only;
  # wall time is recorded for display.

  use GenServer
  require Logger

  alias Tightbeam.OwnerAlerts.MemoryPressure.{Marker, Probe, Recorder}

  @interval_ms 15_000
  @open_run_ms 120_000
  @late_ms 30_000
  @close_ms 900_000
  @latest_write_ms 60_000
  # R4: a run that ends without an episode keeps its marker this long, so a
  # flap near the threshold costs one write instead of a write and a delete.
  @unopened_delete_ms 60_000
  @boot_retry_ms 60_000

  def start_link(opts),
    do: GenServer.start_link(__MODULE__, opts, name: Keyword.fetch!(opts, :name))

  @impl true
  def init(opts) do
    # An orderly stop reaches terminate/2, which deletes an unopened marker.
    Process.flag(:trap_exit, true)

    state = %{
      recorder: Keyword.fetch!(opts, :recorder),
      marker: Keyword.fetch!(opts, :marker),
      state_dir: Keyword.fetch!(opts, :state_dir),
      probe: Probe.new(opts),
      host: Keyword.get_lazy(opts, :host, &Tightbeam.Placement.local_host_name/0),
      clock: Keyword.get(opts, :clock, fn -> System.monotonic_time(:millisecond) end),
      wall_clock: Keyword.get(opts, :wall_clock, fn -> System.system_time(:millisecond) end),
      manual?: Keyword.get(opts, :interval) == :manual,
      os: Keyword.get_lazy(opts, :os, &:os.type/0),
      clock_source: Keyword.get_lazy(opts, :clock_source, &clock_source/0),
      booted?: false,
      owner: nil,
      sampling?: false,
      tick: nil,
      prev_at: nil,
      run: nil,
      episode: nil,
      last_write_at: nil,
      delete_at: nil,
      owner_alerts: Keyword.get(opts, :owner_alerts, Tightbeam.OwnerAlerts),
      ready_waiters: []
    }

    # The boot reads the database, so it runs after init returns: a slow
    # database does not hold up the gateway's later children.
    {:ok, state, {:continue, :boot}}
  end

  @impl true
  def handle_continue(:boot, state), do: {:noreply, boot(state)}

  # M6: a marker found at start is reported and deleted before sampling
  # starts afresh. Once that is recorded (or there was nothing to record),
  # the delivery process is told it may run its boot pass, so a first alert
  # the restart supersedes is withdrawn before anything can send it.
  defp boot(state) do
    found = Marker.read(state.state_dir)

    case Recorder.boot(state.recorder, found, state.wall_clock.()) do
      {:ok, owner} ->
        if found != :none, do: Marker.delete(state.marker)
        GenServer.cast(state.owner_alerts, :memory_pressure_ready)
        Enum.each(state.ready_waiters, &GenServer.cast(&1, :memory_pressure_ready))
        alerts(%{state | booted?: true, ready_waiters: []}, owner)

      {:error, reason} ->
        Logger.error("memory pressure start deferred: #{reason}")
        Process.send_after(self(), :boot, @boot_retry_ms)
        state
    end
  end

  @impl true
  def handle_call(:sample, _from, %{sampling?: true} = state) do
    state = sample(state)
    {:reply, %{run: state.run != nil, episode: state.episode != nil}, state}
  end

  def handle_call(:sample, _from, state), do: {:reply, :disabled, state}

  @impl true
  def handle_cast({:alerts, owner}, %{booted?: true} = state),
    do: {:noreply, alerts(state, owner)}

  def handle_cast({:alerts, _owner}, state), do: {:noreply, state}

  def handle_cast({:opened, opened_at, result}, state),
    do: {:noreply, opened(state, opened_at, result)}

  # A delivery process that started gated asks whether the boot is recorded.
  # It may ask before or after the boot finishes; either way it is told once.
  def handle_cast({:notify_ready, pid}, %{booted?: true} = state) do
    GenServer.cast(pid, :memory_pressure_ready)
    {:noreply, state}
  end

  def handle_cast({:notify_ready, pid}, state),
    do: {:noreply, %{state | ready_waiters: [pid | state.ready_waiters]}}

  @impl true
  def handle_info(:boot, %{booted?: false} = state), do: {:noreply, boot(state)}

  def handle_info({:tick, token}, %{sampling?: true, tick: {token, _timer}} = state),
    do: {:noreply, state |> sample() |> schedule(@interval_ms)}

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(reason, state) do
    # M6: an orderly stop deletes a marker whose run opened no episode, so a
    # routine restart during a passing spike does not alert. A kill leaves it.
    if orderly?(reason) and state.sampling? and is_nil(state.episode) and
         (state.run != nil or state.delete_at != nil) do
      Marker.delete(state.marker)
      Marker.flush(state.marker)
    end

    :ok
  end

  defp orderly?(reason), do: reason in [:normal, :shutdown] or match?({:shutdown, _}, reason)

  ## On and off (§7.1)

  defp alerts(%{owner: owner} = state, owner), do: state

  defp alerts(state, owner) do
    state =
      if state.owner,
        do: stop_sampling(state, if(owner, do: "owner-changed", else: "alerts-cleared")),
        else: state

    state = %{state | owner: owner}
    if owner, do: start_sampling(state), else: state
  end

  # M1: without /proc/meminfo, or off Linux, one lifecycle event says memory
  # alerts are unavailable and the sampler does not run.
  defp start_sampling(%{os: {:unix, :linux}} = state) do
    case Probe.sample(state.probe) do
      {:ok, sample} ->
        Recorder.lifecycle(state.recorder, "memory_pressure_sampler_started", %{
          host: state.host,
          clockSource: state.clock_source,
          intervalMs: @interval_ms,
          pressureStallInformation: is_number(sample["someAvg60"])
        })

        schedule(%{fresh(state) | sampling?: true}, 0)

      :error ->
        unavailable(state, "meminfo-unreadable")
    end
  end

  defp start_sampling(state), do: unavailable(state, "not-linux")

  defp unavailable(state, reason) do
    Recorder.lifecycle(state.recorder, "memory_pressure_unavailable", %{
      host: state.host,
      reason: reason
    })

    state
  end

  # §7.1 C2-off: the sampler stops, its marker is deleted, and an episode
  # open at that moment closes with reason `alerts-off`.
  defp stop_sampling(state, cause) do
    state = cancel_tick(state)

    if state.episode,
      do: close(state, state.wall_clock.(), "alerts-off", %{cause: cause}),
      else: if(state.sampling?, do: Marker.delete(state.marker))

    %{fresh(state) | sampling?: false}
  end

  defp fresh(state),
    do: %{state | prev_at: nil, run: nil, episode: nil, last_write_at: nil, delete_at: nil}

  defp schedule(%{manual?: true} = state, _delay), do: state

  defp schedule(state, delay) do
    token = make_ref()
    timer = Process.send_after(self(), {:tick, token}, delay)
    %{state | tick: {token, timer}}
  end

  defp cancel_tick(%{tick: {_token, timer}} = state) do
    Process.cancel_timer(timer)
    %{state | tick: nil}
  end

  defp cancel_tick(state), do: state

  ## Samples

  defp sample(state) do
    at = state.clock.()
    wall = state.wall_clock.()

    case Probe.sample(state.probe) do
      {:ok, sample} ->
        step(state, sample, at, wall)

      :error ->
        # Not a sample: it neither extends nor ends a run, and the next
        # sample is not judged late against it.
        Logger.warning("memory pressure sample skipped: /proc/meminfo could not be read")
        %{state | prev_at: nil}
    end
  rescue
    error ->
      Logger.error("memory pressure sample failed: #{Exception.message(error)}")
      state
  end

  defp step(state, sample, at, wall) do
    late? = is_integer(state.prev_at) and at - state.prev_at > @late_ms
    state = %{state | prev_at: at}
    pressure? = Probe.pressure?(sample)

    cond do
      state.episode -> in_episode(state, sample, at, wall)
      state.run && pressure? -> state |> keep(sample, wall) |> continue_run(at, late?)
      state.run -> end_run(state, at, wall)
      pressure? -> start_run(state, sample, at, wall, late?)
      true -> idle(state, at)
    end
  end

  # M1's write at the run's end: the marker records when the run ended, so a
  # restart inside the R4 window does not report the spike as ongoing (M6).
  defp end_run(state, at, wall) do
    state = write(state, at, :run_end, wall)
    %{state | run: nil, delete_at: at + @unopened_delete_ms}
  end

  defp keep(%{run: run} = state, sample, wall),
    do: %{state | run: %{run | samples: run.samples + 1, last: sample, last_at: wall}}

  # A2b: the marker is written at a run's first pressure sample. A new run
  # inside the R4 window simply overwrites the previous run's marker.
  defp start_run(state, sample, at, wall, late?) do
    run = %{started_at: at, started_wall: wall, samples: 1, last: sample, last_at: wall}
    state = write(%{state | run: run, delete_at: nil}, at, :run_start)
    if late?, do: open(state, wall), else: state
  end

  # M4: open at the first pressure sample of a run of at least 120 s and two
  # samples, or at a pressure sample more than 30 s after the previous one.
  defp continue_run(%{run: run} = state, at, late?) do
    if late? or (at - run.started_at >= @open_run_ms and run.samples >= 2),
      do: open(state, run.last_at),
      else: write_latest(state, at)
  end

  defp idle(%{delete_at: due} = state, at) when is_integer(due) and at >= due do
    Marker.delete(state.marker)
    %{state | delete_at: nil, last_write_at: nil}
  end

  defp idle(state, _at), do: state

  defp open(state, wall) do
    request = %{
      host: state.host,
      episode_opened_at: wall,
      run_started_at: state.run.started_wall,
      sample: state.run.last,
      populations: Probe.populations(state.probe)
    }

    episode = %{
      opened_at: wall,
      request: request,
      committed?: false,
      in_flight?: false,
      clear_since: nil
    }

    send_open(%{state | episode: episode})
  end

  defp send_open(%{episode: episode} = state) do
    Recorder.open(state.recorder, episode.request)
    %{state | episode: %{episode | in_flight?: true}}
  end

  # M4: the marker records episodeOpenedAt once the open has committed. A
  # reply for an episode that has since ended changes nothing (F1).
  defp opened(%{episode: %{opened_at: opened_at} = episode} = state, opened_at, result) do
    case result do
      :opened ->
        state = %{state | episode: %{episode | committed?: true, in_flight?: false}}
        write(state, state.clock.(), :episode_open)

      :off ->
        alerts(state, nil)

      {:error, _reason} ->
        %{state | episode: %{episode | in_flight?: false}}
    end
  end

  defp opened(state, _opened_at, _result), do: state

  # M5: once open, an episode closes after 15 continuous minutes of clear
  # samples; any other sample restarts that count.
  defp in_episode(state, sample, at, wall) do
    state = keep(state, sample, wall)
    clear_since = if Probe.clear?(sample), do: state.episode.clear_since || at
    state = %{state | episode: %{state.episode | clear_since: clear_since}}

    if clear_since && at - clear_since >= @close_ms do
      close(state, wall, "cleared", %{})
    else
      episode = state.episode
      state = if episode.committed? or episode.in_flight?, do: state, else: send_open(state)
      write_latest(state, at)
    end
  end

  defp close(state, wall, reason, detail) do
    Recorder.close(state.recorder, %{
      host: state.host,
      episode_opened_at: state.episode.opened_at,
      ended_at: wall,
      reason: reason,
      detail: detail
    })

    Marker.delete(state.marker)
    %{state | run: nil, episode: nil, last_write_at: nil, delete_at: nil}
  end

  ## The marker

  defp write_latest(state, at) do
    if is_integer(state.last_write_at) and at - state.last_write_at < @latest_write_ms,
      do: state,
      else: write(state, at, :latest)
  end

  defp write(state, at, reason, ended_at \\ nil) do
    Marker.put(state.marker, marker(state, ended_at), reason)
    %{state | last_write_at: at}
  end

  # runEndedAt is null while the run stands; a new run's first write resets it.
  defp marker(%{run: run, episode: episode} = state, ended_at) do
    %{
      "host" => state.host,
      "runStartedAt" => run.started_wall,
      "runEndedAt" => ended_at,
      "episodeOpenedAt" => if(episode && episode.committed?, do: episode.opened_at),
      "lastSampleAt" => run.last_at,
      "lastSample" => run.last
    }
  end

  # R2: the OS clock behind System.monotonic_time. On Linux it is
  # CLOCK_MONOTONIC, which does not advance across suspend.
  defp clock_source do
    info = :erlang.system_info(:os_monotonic_time_source)
    to_string(Keyword.get(info, :clock_id) || Keyword.get(info, :function) || "unknown")
  end
end
