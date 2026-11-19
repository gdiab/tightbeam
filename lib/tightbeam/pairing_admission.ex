defmodule Tightbeam.PairingAdmission do
  @moduledoc """
  Admission for coded pairings (stage1-v8 S2.2), decided before any Argon2id work:

  - **Rate:** at most 30 coded pairings a minute, gateway-wide, counted at admission.
  - **Concurrency:** at most 2 coded pairings in verification at once, with a bounded
    queue of 4. A request that finds both full is refused at once; a queued request
    waits at most 5 seconds, then is refused.

  So Argon2id memory across the gateway never exceeds 2 × 64 MiB, whatever the burst.
  Refusals are `{:error, :rate_limited}`. A caller that dies releases its slot.
  """

  use GenServer

  @defaults [rate_per_minute: 30, slots: 2, queue: 4, wait_ms: 5_000]

  def start_link(opts) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, Keyword.merge(@defaults, opts), name: name)
  end

  @doc "Run `fun` inside an admission slot, or refuse with `{:error, :rate_limited}`."
  @spec run(GenServer.server(), (-> term())) :: {:ok, term()} | {:error, :rate_limited}
  def run(server, fun) do
    case GenServer.call(server, :acquire, :infinity) do
      {:granted, ref} ->
        try do
          {:ok, fun.()}
        after
          GenServer.cast(server, {:release, ref})
        end

      :rate_limited ->
        {:error, :rate_limited}
    end
  end

  @doc "Counts for tests: active, queued, and the largest active count ever seen."
  def stats(server), do: GenServer.call(server, :stats)

  @impl true
  def init(opts) do
    {:ok,
     %{
       opts: Map.new(opts),
       active: %{},
       queue: :queue.new(),
       admitted: :queue.new(),
       peak: 0
     }}
  end

  @impl true
  def handle_call(:acquire, {pid, _} = from, state) do
    now = System.monotonic_time(:millisecond)
    state = prune(state, now)

    cond do
      :queue.len(state.admitted) >= state.opts.rate_per_minute ->
        {:reply, :rate_limited, state}

      map_size(state.active) < state.opts.slots ->
        {ref, state} = activate(%{state | admitted: :queue.in(now, state.admitted)}, pid)
        {:reply, {:granted, ref}, state}

      :queue.len(state.queue) < state.opts.queue ->
        timer = Process.send_after(self(), {:expire, from}, state.opts.wait_ms)
        state = %{state | admitted: :queue.in(now, state.admitted)}
        {:noreply, %{state | queue: :queue.in({from, timer}, state.queue)}}

      true ->
        {:reply, :rate_limited, state}
    end
  end

  def handle_call(:stats, _from, state) do
    {:reply, %{active: map_size(state.active), queued: :queue.len(state.queue), peak: state.peak},
     state}
  end

  @impl true
  def handle_cast({:release, ref}, state), do: {:noreply, release(state, ref)}

  @impl true
  def handle_info({:expire, from}, state) do
    {expired, rest} = Enum.split_with(:queue.to_list(state.queue), fn {f, _} -> f == from end)

    if expired != [], do: GenServer.reply(from, :rate_limited)
    {:noreply, %{state | queue: :queue.from_list(rest)}}
  end

  def handle_info({:DOWN, ref, :process, _pid, _reason}, state),
    do: {:noreply, release(state, ref)}

  # The caller's monitor reference is its slot: a caller that dies releases it.
  defp activate(state, pid) do
    ref = Process.monitor(pid)
    active = Map.put(state.active, ref, pid)
    {ref, %{state | active: active, peak: max(state.peak, map_size(active))}}
  end

  defp release(state, ref) do
    case Map.pop(state.active, ref) do
      {nil, _} ->
        state

      {_pid, active} ->
        Process.demonitor(ref, [:flush])
        promote(%{state | active: active})
    end
  end

  defp promote(state) do
    case :queue.out(state.queue) do
      {{:value, {{pid, _} = from, timer}}, rest} ->
        Process.cancel_timer(timer)
        {ref, state} = activate(%{state | queue: rest}, pid)
        GenServer.reply(from, {:granted, ref})
        state

      {:empty, _} ->
        state
    end
  end

  defp prune(state, now) do
    cutoff = now - 60_000

    admitted =
      state.admitted
      |> :queue.to_list()
      |> Enum.drop_while(&(&1 <= cutoff))
      |> :queue.from_list()

    %{state | admitted: admitted}
  end
end
