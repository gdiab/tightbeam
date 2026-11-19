defmodule Tightbeam.UserCommands do
  @moduledoc """
  User commands: George's path from Clawline (core-v8 C9-C11).

  A chat message whose whole trimmed text is one line beginning `/tightbeam`
  followed by whitespace is a user command. On a device-authenticated connection
  it is dispatched with authentication class `device`, the connection's user and
  the connection's device, so the protected-act gate (C2-C4) and the ruling gate
  (C12) apply. It is never delivered to a model and never enqueues a turn: the
  command and its outcome are recorded in that conversation's transcript.

  On any other connection the command is refused `user_authentication_required`,
  and it is neither executed nor delivered.
  """

  alias Tightbeam.{DB, Devices, Dispatch, GrantAuth, PairingFreeze, Projection}
  alias Tightbeam.DB.Txn

  @prefix "/tightbeam"

  @usage %{
    "pending-devices" => "/tightbeam pending-devices",
    "approve-device" => "/tightbeam approve-device <deviceId> [<userId>]",
    "deny-device" => "/tightbeam deny-device <deviceId>",
    "revoke-device" => "/tightbeam revoke-device <deviceId>",
    "promote-user" => "/tightbeam promote-user <userId>",
    "demote-user" => "/tightbeam demote-user <userId>",
    "add-user" => "/tightbeam add-user <userId> [--admin]",
    "remove-user" => "/tightbeam remove-user <userId>",
    "register-host" =>
      "/tightbeam register-host <name> <ssh-dest> <base-dir> [--cli-bin <path>] [--adapter-bin-dir <path>]",
    "rule" => "/tightbeam rule <ref> <label>",
    "respond" => "/tightbeam respond <ref> <text>"
  }

  @typedoc "A parsed command: a dispatchable act, the pending-devices read, or malformed."
  @type parsed ::
          {:act, String.t(), map()}
          | {:rule, String.t(), String.t(), :label | :text}
          | :pending_devices
          | {:malformed, String.t()}

  @doc "Whether `content` is a user command (C9): one trimmed line, `/tightbeam` then whitespace."
  @spec command?(String.t()) :: boolean()
  def command?(content) when is_binary(content) do
    text = String.trim(content)

    not String.contains?(text, ["\n", "\r"]) and
      Regex.match?(~r/\A#{Regex.escape(@prefix)}\s/u, text)
  end

  def command?(_content), do: false

  @doc "The refusal for a user command on a connection that is not device-authenticated."
  @spec unauthenticated_refusal() :: %{code: String.t(), message: String.t()}
  def unauthenticated_refusal do
    %{
      code: "user_authentication_required",
      message:
        "/tightbeam commands run only from a paired Tightbeam device app, such as Clawline " <>
          "on your phone. This connection is not device-authenticated, so the command was " <>
          "not executed and not delivered."
    }
  end

  @doc "Parse a user command's text. Anything outside the exact forms is malformed."
  @spec parse(String.t()) :: parsed()
  def parse(content) do
    text = String.trim(content)
    rest = text |> String.replace_prefix(@prefix, "") |> String.trim_leading()

    case String.split(rest, ~r/\s+/u, parts: 2) do
      [sub, args] -> parse(sub, String.trim(args))
      [sub] -> parse(sub, "")
    end
  end

  defp parse("pending-devices", ""), do: :pending_devices

  defp parse("approve-device", args) do
    case words(args) do
      [device_id] -> {:act, "approve-device", %{device_id: device_id}}
      [device_id, user_id] -> {:act, "approve-device", %{device_id: device_id, user_id: user_id}}
      _ -> malformed("approve-device")
    end
  end

  defp parse(verb, args) when verb in ["deny-device", "revoke-device"] do
    case words(args) do
      [device_id] -> {:act, verb, %{device_id: device_id}}
      _ -> malformed(verb)
    end
  end

  defp parse(sub, args) when sub in ["promote-user", "demote-user"] do
    case words(args) do
      [user_id] -> {:act, "promote-user", %{user_id: user_id, is_admin: sub == "promote-user"}}
      _ -> malformed(sub)
    end
  end

  defp parse("add-user", args) do
    case words(args) do
      [user_id] when user_id != "--admin" ->
        {:act, "add-user", %{user_id: user_id, is_admin: false}}

      [user_id, "--admin"] when user_id != "--admin" ->
        {:act, "add-user", %{user_id: user_id, is_admin: true}}

      _ ->
        malformed("add-user")
    end
  end

  defp parse("remove-user", args) do
    case words(args) do
      [user_id] -> {:act, "remove-user", %{user_id: user_id}}
      _ -> malformed("remove-user")
    end
  end

  defp parse("register-host", args) do
    case words(args) do
      [name, ssh, base_dir | flags] ->
        case register_flags(flags, %{}) do
          {:ok, extra} ->
            {:act, "register-host", Map.merge(%{name: name, ssh: ssh, base_dir: base_dir}, extra)}

          :error ->
            malformed("register-host")
        end

      _ ->
        malformed("register-host")
    end
  end

  defp parse(sub, args) when sub in ["rule", "respond"] do
    case String.split(args, ~r/\s+/u, parts: 2) do
      [ref, value] when value != "" ->
        {:rule, ref, String.trim(value), if(sub == "rule", do: :label, else: :text)}

      _ ->
        malformed(sub)
    end
  end

  defp parse(sub, _args) do
    case Map.fetch(@usage, sub) do
      {:ok, _} -> malformed(sub)
      :error -> {:malformed, "unknown command. Forms: " <> Enum.join(Map.values(@usage), "; ")}
    end
  end

  defp register_flags([], acc), do: {:ok, acc}

  defp register_flags(["--cli-bin", path | rest], acc) when not is_map_key(acc, :cli_bin),
    do: register_flags(rest, Map.put(acc, :cli_bin, path))

  defp register_flags(["--adapter-bin-dir", path | rest], acc)
       when not is_map_key(acc, :adapter_bin_dir),
       do: register_flags(rest, Map.put(acc, :adapter_bin_dir, path))

  defp register_flags(_flags, _acc), do: :error

  defp words(""), do: []
  defp words(args), do: String.split(args, ~r/\s+/u, trim: true)

  defp malformed(sub), do: {:malformed, "usage: " <> Map.fetch!(@usage, sub)}

  @doc """
  Execute a parsed command for a device-authenticated connection and return the
  outcome text recorded in the transcript. `ctx` carries `:db`, `:handlers`,
  `:user_id` and `:device_id`.
  """
  @spec execute(parsed(), map()) :: String.t()
  def execute({:malformed, why}, _ctx), do: "Refused, nothing was executed: #{why}"

  def execute(:pending_devices, ctx), do: pending_devices(ctx)

  def execute({:act, verb, params}, ctx) do
    case Dispatch.dispatch(ctx.db, ctx.handlers, call(ctx, verb, params)) do
      {:ok, result} -> "Done: #{verb}. " <> act_details(ctx, verb, params, result)
      {:error, error} -> refused(error)
      {:decision_pending, id} -> "Waiting on decision request #{id}; nothing changed yet."
    end
  end

  def execute({:rule, ref, value, mode}, ctx) do
    case resolve_ref(ctx.db, ref) do
      {:ok, request_id} ->
        answer =
          if mode == :label, do: %{decision: value}, else: %{response: value}

        params = Map.put(answer, :request_id, request_id)

        case Dispatch.dispatch(ctx.db, ctx.handlers, call(ctx, "operator-rule", params)) do
          {:ok, _result} -> "Ruled #{request_id}: #{value}"
          {:error, error} -> refused(error)
          {:decision_pending, id} -> "Waiting on decision request #{id}; nothing changed yet."
        end

      {:error, why} ->
        "Refused, nothing was executed: #{why}"
    end
  end

  defp call(ctx, verb, params) do
    %{
      verb: verb,
      origin: "user:#{ctx.user_id}",
      principal: {:user, ctx.user_id},
      auth_class: "device",
      auth_device_id: ctx.device_id,
      session_key: nil,
      params: params
    }
  end

  defp refused(error) do
    "Refused (#{error[:code] || "server_error"}): #{error[:message] || "no message"}"
  end

  defp act_details(ctx, verb, params, _result)
       when verb in ["approve-device", "deny-device", "revoke-device"] do
    case Devices.by_id(ctx.db, params.device_id) do
      nil -> "Device #{params.device_id}."
      device -> device_line(device)
    end
  end

  defp act_details(_ctx, "register-host", params, _result) do
    "Host #{params.name}: SSH destination #{params.ssh}, base directory #{params.base_dir}."
  end

  defp act_details(_ctx, "promote-user", params, _result) do
    "User #{params.user_id} is #{if params.is_admin, do: "an admin", else: "not an admin"}."
  end

  defp act_details(_ctx, verb, params, _result) when verb in ["add-user", "remove-user"] do
    "User #{params.user_id}."
  end

  defp device_line(device) do
    "Device #{device.device_id} (#{device.claimed_name}; platform #{device.platform || "unknown"}; " <>
      "model #{device.model || "unknown"}; paired #{format_time(device.created_at)}) " <>
      "is #{device.status} for user #{device.user_id}."
  end

  # C11: answered from the gateway's own rows, and only for an admin-paired device.
  defp pending_devices(ctx) do
    {:ok, admin?} =
      DB.transaction(ctx.db, fn txn ->
        match?(
          %{is_admin: true},
          GrantAuth.device_user_in_txn(txn, call(ctx, "pending-devices", %{}))
        )
      end)

    if admin? do
      frozen =
        if PairingFreeze.read().lifted,
          do: "Pairing is LIFTED (the unfreeze file is present).",
          else: "Pairing is frozen."

      case Devices.list_pending(ctx.db) do
        [] ->
          frozen <> " No pending devices."

        devices ->
          lines =
            Enum.map(devices, fn d ->
              "- #{d.device_id}: #{d.claimed_name}, claimed user #{d.user_id}, platform " <>
                "#{d.platform || "unknown"}, model #{d.model || "unknown"}, paired " <>
                format_time(d.created_at)
            end)

          Enum.join([frozen <> " Pending devices:" | lines], "\n")
      end
    else
      refused(%{code: "forbidden", message: "pending-devices requires an admin's paired device"})
    end
  end

  @doc """
  Resolve a request reference (C9): the full id, or `dr_` and at least 8
  hexadecimal characters that prefix exactly one request.
  """
  @spec resolve_ref(DB.server(), String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def resolve_ref(db, ref) do
    {:ok, result} =
      DB.transaction(db, fn txn ->
        cond do
          Txn.q(txn, "SELECT 1 FROM decision_requests WHERE id = ?1", [ref]) == [[1]] ->
            {:ok, ref}

          Regex.match?(~r/\Adr_[0-9a-f]{8,}\z/, ref) ->
            case Txn.q(
                   txn,
                   "SELECT id FROM decision_requests WHERE substr(id, 1, ?2) = ?1 LIMIT 2",
                   [ref, String.length(ref)]
                 ) do
              [[id]] -> {:ok, id}
              [] -> {:error, "no decision request matches #{ref}"}
              _ -> {:error, "#{ref} matches more than one decision request; give more of it"}
            end

          true ->
            {:error, "#{ref} is not a decision request id or a dr_ prefix of 8+ hex characters"}
        end
      end)

    result
  end

  @doc "Record the command and its outcome in the conversation, without a turn."
  @spec record(DB.server(), map(), String.t()) ::
          {:recorded, map()} | {:duplicate, map()} | {:conflict, map()}
  def record(db, input, content) do
    {:ok, result} =
      DB.transaction(db, fn txn ->
        Projection.append_in_txn(txn, %{
          session_key: input.session_key,
          role: "user",
          content: content,
          sender: "user:#{input.user_id}",
          device_id: input.device_id,
          client_message_id: input.client_message_id
        })
      end)

    case result do
      {:appended, message} -> {:recorded, message}
      other -> other
    end
  end

  @doc "Append the outcome as a Tightbeam notice in the same conversation."
  @spec record_outcome(DB.server(), String.t(), String.t()) :: map()
  def record_outcome(db, session_key, text) do
    {:appended, message} = Projection.append_substrate(db, session_key, text)
    message
  end

  defp format_time(ms) when is_integer(ms) do
    case DateTime.from_unix(ms, :millisecond) do
      {:ok, at} -> DateTime.to_iso8601(at)
      _ -> Integer.to_string(ms)
    end
  end

  defp format_time(_), do: "unknown"
end
