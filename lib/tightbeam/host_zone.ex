defmodule Tightbeam.HostZone do
  @moduledoc """
  The IANA time zone of a harness host, when the gateway can establish it.

  Only the gateway's own host has a known zone: `:local_time_zone` when
  configured, else `TZ`, else the `/etc/localtime` link. No host-zone source
  exists for a remote host, so its zone is unknown (`nil`), and a provider
  reset written in that host's local time cannot be read (quota companion
  v1.1 §1, B1 known limitation).
  """

  @spec zone(String.t() | nil) :: String.t() | nil
  def zone(host) when is_binary(host) do
    if host == Tightbeam.Placement.local_host_name(), do: local_zone(), else: nil
  end

  def zone(_host), do: nil

  defp local_zone do
    configured = Application.get_env(:tightbeam, :local_time_zone)

    zone =
      cond do
        is_binary(configured) and configured != "" ->
          configured

        (tz = System.get_env("TZ")) not in [nil, ""] ->
          String.trim_leading(tz, ":")

        true ->
          case File.read_link("/etc/localtime") do
            {:ok, target} ->
              case String.split(target, "zoneinfo/", parts: 2) do
                [_, name] -> name
                _ -> nil
              end

            {:error, _} ->
              nil
          end
      end

    if is_binary(zone) and valid?(zone), do: zone, else: nil
  end

  defp valid?(zone) do
    match?({:ok, _}, DateTime.shift_zone(~U[2026-01-01 00:00:00Z], zone, Tz.TimeZoneDatabase))
  end
end
