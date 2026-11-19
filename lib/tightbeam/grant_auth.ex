defmodule Tightbeam.GrantAuth do
  @moduledoc """
  User-authenticated grants and rulings (core fix (A), spec core-v8).

  A credential in a user's name, or a ruling on the owner's question, exists only
  when that person made it through a channel the gateway can verify: a request or
  WebSocket connection carrying an allowlisted device token of a non-removed user.

  The transport derives the call's **authentication class** at its boundary and
  carries it on the call beside `origin` and `principal`:

  - `device`: a validated device token (`auth_device_id` names the device);
  - `org`: the organization credential, whatever user, role or process it names;
  - `session`: a session credential;
  - `none`: nothing was authenticated.

  It is never read from a request body. A call without it is treated as `none`,
  so an internal dispatch can never pass the device gate.

  The protected acts (`approve-device`, `add-user`, `promote-user`, `remove-user`,
  `register-host`, `revoke-device`, `deny-device`, and stage 1's `recovery-enroll`)
  run only for an admin-paired device: the check is repeated inside the act's own
  transaction.
  """

  alias Tightbeam.DB
  alias Tightbeam.DB.Txn

  @protected_verbs ~w(approve-device add-user promote-user remove-user register-host revoke-device deny-device recovery-enroll)

  @shape "user-authenticated-grants-v1-0114"

  @migration_stamp_ddl """
  CREATE TABLE grant_auth_migration (
    id        INTEGER PRIMARY KEY CHECK (id = 0),
    shape     TEXT NOT NULL CHECK (shape = '#{@shape}'),
    appliedAt INTEGER NOT NULL CHECK (appliedAt >= 0)
  )
  """

  # The ruling route marker. A side table, so no existing decision request row is
  # touched (C16) and its row guards stay as they are.
  @ruling_routes_ddl """
  CREATE TABLE decision_request_ruling_routes (
    requestId    TEXT PRIMARY KEY,
    route        TEXT NOT NULL CHECK (route IN ('device','delegated-unverified')),
    authClass    TEXT NOT NULL CHECK (authClass IN ('device','org','session','none')),
    authDeviceId TEXT,
    recordedAt   INTEGER NOT NULL CHECK (recordedAt >= 0),
    CHECK ((authClass = 'device') = (authDeviceId IS NOT NULL))
  )
  """

  # The gateway's last observation of the unfreeze file (C6a transitions).
  @freeze_observation_ddl """
  CREATE TABLE pairing_freeze_observation (
    id         INTEGER PRIMARY KEY CHECK (id = 0),
    state      TEXT NOT NULL CHECK (state IN ('frozen','lifted')),
    observedAt INTEGER NOT NULL CHECK (observedAt >= 0),
    fileMtime  INTEGER
  )
  """

  @tables [
    {"decision_request_ruling_routes", @ruling_routes_ddl},
    {"pairing_freeze_observation", @freeze_observation_ddl}
  ]

  @columns [
    {"events", "authClass", "TEXT", "authClass TEXT"},
    {"events", "authDeviceId", "TEXT", "authDeviceId TEXT"},
    {"events", "pairingFreeze", "TEXT", "pairingFreeze TEXT"},
    {"devices", "tokenCollected", "INTEGER", "tokenCollected INTEGER NOT NULL DEFAULT 0"}
  ]

  @type auth_class :: String.t()

  @doc "The seven verbs only an admin-paired device may perform (C2)."
  @spec protected_verbs() :: [String.t()]
  def protected_verbs, do: @protected_verbs

  @spec protected_verb?(String.t()) :: boolean()
  def protected_verb?(verb), do: verb in @protected_verbs

  @doc "The call's authentication class; absent means nothing was authenticated."
  @spec auth_class(map()) :: auth_class()
  def auth_class(call) do
    case Map.get(call, :auth_class) do
      class when class in ["device", "org", "session"] -> class
      _ -> "none"
    end
  end

  @doc "The authenticating device id, only for class `device`."
  @spec auth_device_id(map()) :: String.t() | nil
  def auth_device_id(call) do
    case {auth_class(call), Map.get(call, :auth_device_id)} do
      {"device", id} when is_binary(id) and id != "" -> id
      _ -> nil
    end
  end

  @doc """
  The event-row authentication fields of a call (C4): its class and its device.
  """
  @spec audit(map()) :: %{
          class: auth_class(),
          device_id: String.t() | nil,
          pairing_freeze: String.t() | nil
        }
  def audit(call) do
    # Stage 1 retires the freeze (S0.1); the column stays, unused (core K6 map).
    %{class: auth_class(call), device_id: auth_device_id(call), pairing_freeze: nil}
  end

  @doc """
  The acting user of a device-authenticated call whose device still holds a token
  of a non-removed user, read inside the caller's transaction; otherwise nil.
  """
  @spec device_user_in_txn(Txn.t(), map()) :: %{user_id: String.t(), is_admin: boolean()} | nil
  def device_user_in_txn(%Txn{} = txn, call) do
    with device_id when is_binary(device_id) <- auth_device_id(call),
         {:user, user_id} <- Map.get(call, :principal),
         [[^user_id, is_admin]] <-
           Txn.q(
             txn,
             """
             SELECT d.userId, u.isAdmin FROM devices d JOIN users u ON u.userId = d.userId
             WHERE d.deviceId = ?1 AND d.status = 'allowlisted' AND d.token IS NOT NULL
               AND u.removedAt IS NULL
             """,
             [device_id]
           ) do
      %{user_id: user_id, is_admin: is_admin == 1}
    else
      _ -> nil
    end
  end

  @doc """
  C2: `:ok` only for an admin-paired device, checked inside the act's transaction.
  A device of a non-admin user gets `forbidden`; every other caller gets the C5
  refusal.
  """
  @spec authorize_in_txn(Txn.t(), map()) :: :ok | map()
  def authorize_in_txn(%Txn{} = txn, call) do
    case device_user_in_txn(txn, call) do
      %{is_admin: true} -> :ok
      %{is_admin: false} -> %{code: "forbidden", message: "admin required"}
      nil -> refusal(call)
    end
  end

  @doc "C2 outside a transaction, for a refusal before any side effect."
  @spec authorize(DB.server(), map()) :: :ok | map()
  def authorize(db, call) do
    {:ok, result} = DB.transaction(db, &authorize_in_txn(&1, call))
    result
  end

  @doc "The C5 refusal for a protected act."
  @spec refusal(map()) :: %{code: String.t(), message: String.t()}
  def refusal(call) do
    verb = Map.get(call, :verb)

    %{
      code: "user_authentication_required",
      message:
        "#{verb} must come from an admin's own paired Tightbeam device app, such as " <>
          "Clawline on their phone. Agent sessions, the organization credential " <>
          "(including --as-user and --as-process) and roles cannot do it. Ask them to " <>
          "send `#{command_text(verb, Map.get(call, :params) || %{})}` from that app."
    }
  end

  @doc "The C13/C15 refusal for a ruling on an owner request."
  @spec ruling_refusal(String.t(), String.t()) :: %{code: String.t(), message: String.t()}
  def ruling_refusal(request_id, owner) do
    %{
      code: "user_authentication_required",
      message:
        "operator-rule on #{request_id} must come from #{owner}'s own paired Tightbeam " <>
          "device app, such as Clawline on their phone. Agent sessions, the organization " <>
          "credential (including --as-user and --as-process) and roles cannot rule it. Ask " <>
          "#{owner} to send `/tightbeam rule #{request_id} <option>` from that app, or tell " <>
          "#{owner}'s Main."
    }
  end

  @doc "C13: the raiser session may not rule its own request."
  @spec self_ruling_refusal(String.t(), String.t()) :: %{code: String.t(), message: String.t()}
  def self_ruling_refusal(request_id, owner) do
    %{
      code: "self_ruling_forbidden",
      message:
        "#{request_id} was raised by this session, which cannot rule it. Ask #{owner} to " <>
          "send `/tightbeam rule #{request_id} <option>` from Clawline, or tell Main."
    }
  end

  @doc "C14: a delegated ruling must quote the instruction and name the request."
  @spec delegation_refusal(String.t()) :: %{code: String.t(), message: String.t()}
  def delegation_refusal(request_id) do
    %{
      code: "delegation_rationale_required",
      message:
        "Quote George's instruction in --rationale and name #{request_id} in it, or ask " <>
          "George to send `/tightbeam rule #{request_id} <option>` from Clawline."
    }
  end

  @doc """
  C14: whether `rationale` names `request_id`, as the full id or as `dr_` followed by
  at least 8 hexadecimal characters that prefix this request and no other open or
  closed request.
  """
  @spec rationale_names_request_in_txn?(Txn.t(), String.t() | nil, String.t()) :: boolean()
  def rationale_names_request_in_txn?(_txn, rationale, _request_id) when not is_binary(rationale),
    do: false

  def rationale_names_request_in_txn?(%Txn{} = txn, rationale, request_id) do
    cond do
      String.contains?(rationale, request_id) ->
        true

      true ->
        ~r/dr_[0-9a-f]{8,}/i
        |> Regex.scan(rationale)
        |> Enum.any?(fn [prefix] ->
          prefix = String.downcase(prefix)

          String.starts_with?(request_id, prefix) and
            Txn.q(
              txn,
              "SELECT COUNT(*) FROM decision_requests WHERE substr(id, 1, ?2) = ?1",
              [prefix, String.length(prefix)]
            ) == [[1]]
        end)
    end
  end

  @doc "Record the ruling route marker for an owner request (C12, C14)."
  @spec record_ruling_route_in_txn(Txn.t(), String.t(), String.t(), map()) :: :ok
  def record_ruling_route_in_txn(%Txn{} = txn, request_id, route, call)
      when route in ["device", "delegated-unverified"] do
    Txn.q(
      txn,
      """
      INSERT INTO decision_request_ruling_routes
        (requestId, route, authClass, authDeviceId, recordedAt)
      VALUES (?1, ?2, ?3, ?4, ?5)
      """,
      [request_id, route, auth_class(call), auth_device_id(call), now()]
    )

    :ok
  end

  @doc "The recorded ruling route of a request, or nil for history and other routes."
  @spec ruling_route(DB.server(), String.t()) :: map() | nil
  def ruling_route(db, request_id) do
    {:ok, rows} =
      DB.query(
        db,
        "SELECT route, authClass, authDeviceId, recordedAt FROM decision_request_ruling_routes WHERE requestId = ?1",
        [request_id]
      )

    case rows do
      [[route, class, device_id, recorded_at]] ->
        %{route: route, auth_class: class, auth_device_id: device_id, recorded_at: recorded_at}

      [] ->
        nil
    end
  end

  @doc "The exact `/tightbeam` user command that performs a protected act (C5, C9)."
  @spec command_text(String.t(), map()) :: String.t()
  def command_text(verb, params) do
    p = fn key -> param(params, key) end

    case verb do
      "approve-device" ->
        join(["/tightbeam approve-device", p.(:user_id)])

      "recovery-enroll" ->
        "/tightbeam recovery-enroll"

      "deny-device" ->
        join(["/tightbeam deny-device", p.(:device_id) || "<deviceId>"])

      "revoke-device" ->
        join(["/tightbeam revoke-device", p.(:device_id) || "<deviceId>"])

      "promote-user" ->
        sub = if param(params, :is_admin) == false, do: "demote-user", else: "promote-user"
        join(["/tightbeam #{sub}", p.(:user_id) || "<userId>"])

      "add-user" ->
        admin = if param(params, :is_admin) == true, do: "--admin"
        join(["/tightbeam add-user", p.(:user_id) || "<userId>", admin])

      "remove-user" ->
        join(["/tightbeam remove-user", p.(:user_id) || "<userId>"])

      "register-host" ->
        join([
          "/tightbeam register-host",
          p.(:name) || "<name>",
          p.(:ssh) || p.(:name) || "<ssh-dest>",
          p.(:base_dir) || "<base-dir>",
          flag("--cli-bin", p.(:cli_bin)),
          flag("--adapter-bin-dir", p.(:adapter_bin_dir))
        ])

      other ->
        "/tightbeam #{other}"
    end
  end

  defp param(params, key) do
    case Map.get(params, key, Map.get(params, Atom.to_string(key))) do
      value when is_binary(value) and value != "" -> value
      value when is_boolean(value) -> value
      _ -> nil
    end
  end

  defp flag(_name, nil), do: nil
  defp flag(name, value), do: "#{name} #{value}"

  defp join(parts), do: parts |> Enum.reject(&is_nil/1) |> Enum.join(" ")

  ## Schema

  @doc "Add the C17 fields once, over any current schema, or validate them."
  @spec ensure_schema(DB.server()) :: :ok
  def ensure_schema(db \\ DB) do
    case DB.migration_transaction(db, :user_authenticated_grants, [], [], &migrate_in_txn/1) do
      {:ok, :ok} -> :ok
      {:error, error} -> raise error
    end
  end

  defp migrate_in_txn(%Txn{} = txn) do
    case Txn.q(
           txn,
           "SELECT sql FROM sqlite_master WHERE type='table' AND name='grant_auth_migration'"
         ) do
      [] ->
        apply_in_txn(txn)

      [[sql]] ->
        unless normalize(sql) == normalize(@migration_stamp_ddl),
          do: shape_error("incompatible_grant_auth_migration_ddl: #{inspect(sql)}")

        case Txn.q(txn, "SELECT id, shape, appliedAt FROM grant_auth_migration") do
          [[0, @shape, applied_at]] when is_integer(applied_at) -> validate_in_txn!(txn)
          rows -> shape_error("incompatible_grant_auth_migration_stamp: #{inspect(rows)}")
        end
    end
  end

  defp apply_in_txn(txn) do
    Enum.each(@columns, fn {table, column, _type, definition} ->
      if column_info(txn, table, column) != nil,
        do: shape_error("incompatible_grant_auth_unstamped_column: #{table}.#{column}")

      :ok = Txn.exec(txn, "ALTER TABLE #{table} ADD COLUMN #{definition}")
    end)

    # C6a: every token that exists at installation counts as collected.
    Txn.q(txn, "UPDATE devices SET tokenCollected = 1 WHERE token IS NOT NULL")

    Enum.each(@tables, fn {name, ddl} ->
      if Txn.q(txn, "SELECT 1 FROM sqlite_master WHERE name = ?1", [name]) != [],
        do: shape_error("incompatible_grant_auth_unstamped_table: #{name}")

      :ok = Txn.exec(txn, ddl)
    end)

    :ok = Txn.exec(txn, @migration_stamp_ddl)

    Txn.q(txn, "INSERT INTO grant_auth_migration (id, shape, appliedAt) VALUES (0, ?1, ?2)", [
      @shape,
      now()
    ])

    validate_in_txn!(txn)
  end

  defp validate_in_txn!(txn) do
    Enum.each(@columns, fn {table, column, type, _definition} ->
      case column_info(txn, table, column) do
        [_cid, ^column, ^type | _] ->
          :ok

        other ->
          shape_error("incompatible_grant_auth_column: #{table}.#{column} #{inspect(other)}")
      end
    end)

    Enum.each(@tables, fn {name, ddl} ->
      case Txn.q(txn, "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1", [name]) do
        [[sql]] ->
          unless normalize(sql) == normalize(ddl),
            do: shape_error("incompatible_grant_auth_table: #{name}")

        rows ->
          shape_error("incompatible_grant_auth_table: #{name} #{inspect(rows)}")
      end
    end)

    :ok
  end

  defp column_info(txn, table, column),
    do: Enum.find(Txn.q(txn, "PRAGMA table_info(#{table})"), &(Enum.at(&1, 1) == column))

  defp normalize(sql),
    do:
      sql
      |> String.replace("\"", "")
      |> String.replace(~r/\s+/, " ")
      |> String.trim()
      |> String.trim_trailing(";")

  defp shape_error(message), do: raise(Tightbeam.Schema.ShapeError, message: message)

  defp now, do: System.system_time(:millisecond)
end
