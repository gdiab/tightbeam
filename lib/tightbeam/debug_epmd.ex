defmodule Tightbeam.DebugEpmd do
  @moduledoc false
  # Core fix (A), C21.1 (i): the EPMD module of a hand-enabled debug distribution
  # (rel/env.sh.eex, TIGHTBEAM_DEBUG_DISTRIBUTION=loopback:<port>). The node registers
  # with no EPMD at all, so an EPMD another program started on every interface never
  # learns of it. The node listens only on the loopback port the operator named
  # (`erl_epmd_node_listen_port`, `inet_dist_use_interface`); a peer reaches it with
  # `-erl_epmd_port <port>`. Lookups are the stock module's, which answer that fixed
  # port without asking an EPMD.

  def start_link, do: :ignore

  def register_node(_name, _port), do: {:ok, creation()}
  def register_node(_name, _port, _family), do: {:ok, creation()}

  def listen_port_please(name, host), do: :erl_epmd.listen_port_please(name, host)
  def port_please(name, host), do: :erl_epmd.port_please(name, host)
  def port_please(name, host, timeout), do: :erl_epmd.port_please(name, host, timeout)
  def address_please(name, host, family), do: :erl_epmd.address_please(name, host, family)

  def names(_host), do: {:error, :address}

  # A distribution creation is any 32-bit value above 3; it tells incarnations apart.
  defp creation, do: :rand.uniform(0xFFFFFFF0) + 3
end
