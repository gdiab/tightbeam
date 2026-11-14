defmodule Tightbeam.CredentialHealth do
  @moduledoc false

  import Plug.Conn

  alias Tightbeam.{CliCompatibility, ConnRegistry, LiveBaseAdmission, Org, Placement}
  alias Tightbeam.Wire.RequestObservation

  @rate_key "credential-health"
  @rate_kind :credential_health
  @rate_limit 60
  @rate_window_ms 60_000

  @spec instance(String.t()) :: %{String.t() => String.t()}
  def instance(base_dir) do
    canonical = LiveBaseAdmission.canonical!(base_dir)

    %{
      "id" =>
        :crypto.hash(:sha256, "tightbeam-instance-v1\n" <> canonical)
        |> Base.encode16(case: :lower),
      "host" => Placement.local_host_name()
    }
  end

  @spec handle(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def handle(conn, deps) do
    case admit(deps[:conn_registry] || ConnRegistry) do
      :admitted -> classify(conn, deps)
      :rate_limited -> terminal(conn, 429, "rate_limited")
      :unavailable -> terminal(conn, 503, "unavailable")
    end
  end

  defp admit(registry) do
    try do
      if ConnRegistry.within_rate_limit(
           registry,
           @rate_key,
           @rate_kind,
           @rate_limit,
           @rate_window_ms
         ),
         do: :admitted,
         else: :rate_limited
    rescue
      _error -> :unavailable
    catch
      :exit, _reason -> :unavailable
    end
  end

  defp classify(conn, deps) do
    token = bearer_token(conn)

    result =
      cond do
        is_nil(token) ->
          {:ok, "auth_failed"}

        is_binary(deps[:cli_token]) and token == deps[:cli_token] ->
          {:ok, "ok"}

        true ->
          lookup =
            deps[:credential_health_session_lookup] || (&Org.credential_state_by_cli_token/2)

          case session_state(
                 lookup,
                 deps[:db] || Tightbeam.DB,
                 token,
                 deps[:diagnostics_emit]
               ) do
            {:ok, "active"} -> {:ok, "ok"}
            {:ok, "retired"} -> {:ok, "revoked"}
            {:ok, nil} -> {:ok, "auth_failed"}
            {:error, _reason} -> :unavailable
          end
      end

    # Bound outside the guard: `deps[...]` is Access.get/2, which a guard cannot call.
    instance = deps[:credential_health_instance]

    case result do
      {:ok, result_class} when is_map(instance) ->
        body = %{
          "schemaVersion" => 1,
          "result" => result_class,
          "instance" => instance,
          "version" => CliCompatibility.required_version()
        }

        RequestObservation.result_class(result_class)

        conn
        |> put_resp_header("cache-control", "no-store")
        |> put_resp_content_type("application/json")
        |> send_resp(200, JSON.encode!(body))

      :unavailable ->
        terminal(conn, 503, "unavailable")

      {:ok, _result_class} ->
        terminal(conn, 503, "unavailable")
    end
  end

  defp session_state(lookup, db, token, diagnostics_emit) do
    Tightbeam.DBObservation.with_diagnostics_emit(diagnostics_emit, fn ->
      try do
        lookup.(db, token)
      rescue
        _error -> {:error, :unavailable}
      catch
        :exit, _reason -> {:error, :unavailable}
      end
    end)
  end

  defp terminal(conn, status, result_class) do
    RequestObservation.result_class(result_class)

    conn
    |> put_resp_header("cache-control", "no-store")
    |> put_resp_content_type("application/json")
    |> send_resp(status, ~s({"schemaVersion":1}))
  end

  defp bearer_token(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] when token != "" -> token
      _ -> nil
    end
  end
end
