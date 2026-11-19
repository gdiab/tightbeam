defmodule Tightbeam.DeliveryDeadlines do
  @moduledoc """
  Clears minted tokens never signed in with by their first-sign-in deadline (stage1-v8
  S2.3). Deadlines are rows, so a restart resumes from the table: this process keeps
  one timer for the earliest pending deadline, and a sign-in racing the sweep is
  decided by the token generation in one transaction.
  """

  use GenServer

  alias Tightbeam.DeviceLifecycle

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc "Re-read the earliest deadline (after a coded pairing mints a token)."
  def poke, do: GenServer.cast(__MODULE__, :poke)

  @doc "As `poke/0`, when the gateway's process is running (tests may not start it)."
  def poke_if_running, do: if(Process.whereis(__MODULE__), do: poke(), else: :ok)

  @impl true
  def init(opts), do: {:ok, schedule(%{db: Keyword.fetch!(opts, :db), timer: nil})}

  @impl true
  def handle_cast(:poke, state), do: {:noreply, schedule(state)}

  @impl true
  def handle_info(:due, state) do
    _ = DeviceLifecycle.expire_due(state.db)
    {:noreply, schedule(%{state | timer: nil})}
  end

  defp schedule(state) do
    if state.timer, do: Process.cancel_timer(state.timer)

    case DeviceLifecycle.next_deadline(state.db) do
      nil ->
        %{state | timer: nil}

      deadline ->
        delay = max(deadline - System.system_time(:millisecond), 0) + 50
        %{state | timer: Process.send_after(self(), :due, delay)}
    end
  end
end
