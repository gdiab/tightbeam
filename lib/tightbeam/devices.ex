defmodule Tightbeam.Devices do
  @moduledoc """
  Device pairing + token store (TS reference: src/wire/devices.ts — port its
  behavior exactly; its test file is the acceptance oracle).

  USERS own identity and admin-ness; DEVICES are credentials attached to a
  user (membership). Pairing with a claimed name is a request to join that
  user; approval is the authentication ceremony. The FIRST user ever is admin
  (cold-start rule); `is_admin` on a device is DERIVED from the owning user at
  read time, never stored on the device — admin follows the person, not the
  phone. Tokens are opaque per-device bearers (third credential class,
  gateway-owned; prefix `tbt_`).
  """

  alias Tightbeam.{
    AdminProjection,
    DB,
    GrantAuth,
    StateResources,
    TerminalCredentialFailure,
    UserAdmin
  }

  alias Tightbeam.DB.Txn
  alias Tightbeam.Firehose.Publisher

  @type db :: GenServer.server()

  # Core fix (A), review B1: the ungated in-process writers below (`approve/3`,
  # `deny/2`, `revoke/2`, `add_user/3`, `set_user_admin/3`) exist only in test builds,
  # as fixtures. Production code reaches devices and users only through the gated
  # `*_with_firehose` writers and pairing.
  @test_fixtures Application.compile_env(:tightbeam, :test_fixtures, false)

  @typedoc """
  A device row; `is_admin` is derived from the owning user via JOIN, and a
  removed user confers none. `user_removed` says the owning user is removed.
  """
  @type device :: %{
          device_id: String.t(),
          user_id: String.t(),
          claimed_name: String.t(),
          status: String.t(),
          is_admin: boolean(),
          user_removed: boolean(),
          token: String.t() | nil,
          platform: String.t() | nil,
          model: String.t() | nil,
          created_at: integer()
        }

  @typedoc """
  A user row. `is_admin` is effective admin standing: the stored bit and not
  removed. `stored_admin` is the stored bit itself.
  """
  @type user :: %{
          user_id: String.t(),
          is_admin: boolean(),
          stored_admin: boolean(),
          created_at: integer(),
          removed_at: integer() | nil,
          removed_by: String.t() | nil
        }

  @typedoc """
  Pairing outcome — mirrors the TS PairOutcome union, plus the refusal for a
  device whose user was removed.
  """
  @type pair_outcome ::
          {:paired, device()} | {:pending, device()} | :denied | {:refused, String.t()}

  @ddl """
  CREATE TABLE IF NOT EXISTS users (
    userId    TEXT PRIMARY KEY,
    isAdmin   INTEGER NOT NULL DEFAULT 0,
    createdAt INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS devices (
    deviceId    TEXT PRIMARY KEY,
    userId      TEXT NOT NULL REFERENCES users(userId),
    claimedName TEXT NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('allowlisted','pending','denied')),
    token       TEXT UNIQUE,
    platform    TEXT,
    model       TEXT,
    createdAt   INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS device_versions (
    deviceId   TEXT PRIMARY KEY REFERENCES devices(deviceId),
    rowVersion INTEGER NOT NULL
  );
  """

  # The removal columns are added by the user-removal schema migration
  # (Tightbeam.Schema); a fresh database gets them the same way.
  @user_columns "userId, isAdmin, createdAt, removedAt, removedBy"

  @spec ensure_schema(db()) :: :ok | {:error, term()}
  def ensure_schema(db \\ Tightbeam.DB) do
    with :ok <- DB.execute(db, @ddl), do: AdminProjection.ensure_storage(db)
  end

  @doc """
  Decide one `pair_request` by one-time code (stage1-v8 S2.2). The freeze and its
  escape hatch of core fix (A) no longer apply (S0.1). Returns `{:paired, device}`
  with the new token, or `{:refused, reason, message}`; an uncoded request creates
  no row.
  """
  @spec pair(db(), map(), keyword()) ::
          {:paired, %{device_id: String.t(), user_id: String.t(), token: String.t()}}
          | {:refused, String.t(), String.t()}
  def pair(db \\ Tightbeam.DB, input, opts \\ []),
    do: Tightbeam.DeviceLifecycle.pair(db, input, opts)

  @doc """
  Device by bearer token — ONLY if allowlisted and its user is not removed
  (revoked/pending tokens and removed users' tokens never resolve).
  """
  @spec by_token(db(), String.t()) :: device() | nil
  def by_token(db \\ Tightbeam.DB, token) do
    {:ok, rows} =
      DB.query(
        db,
        select_device_sql() <>
          " WHERE d.token = ?1 AND d.status = 'allowlisted' AND u.removedAt IS NULL",
        [token]
      )

    one_device_or_nil(rows)
  end

  @doc "Device by id regardless of status (for auth-failure reason mapping)."
  @spec by_id(db(), String.t()) :: device() | nil
  def by_id(db \\ Tightbeam.DB, device_id) do
    {:ok, rows} = DB.query(db, select_device_sql() <> " WHERE d.deviceId = ?1", [device_id])
    one_device_or_nil(rows)
  end

  if @test_fixtures do
    @doc """
    Approve a pending device: status → allowlisted, mint a fresh token, and
    attach to the claimed user (or the explicit override `user_id`, creating it
    non-admin if new). Raises on unknown device, and on a removed user.
    """
    @spec approve(db(), String.t(), String.t() | nil) :: device()
    def approve(db \\ Tightbeam.DB, device_id, user_id \\ nil) do
      transaction!(db, fn txn ->
        device = must_get(txn, device_id)
        target = user_id || device.user_id

        if UserAdmin.removed_in_txn?(txn, target),
          do: raise(ArgumentError, "user_removed: #{target}")

        if user_id, do: ensure_user(txn, user_id)

        Txn.q(
          txn,
          """
            UPDATE devices
            SET status = 'allowlisted', userId = COALESCE(?2, userId), token = ?3
            WHERE deviceId = ?1
          """,
          [device_id, user_id, mint_token()]
        )

        stamp_device_in_txn(txn, device_id, now())

        must_get(txn, device_id)
      end)
    end
  end

  if @test_fixtures do
    @doc "Deny a device: status → denied, token cleared. Raises on unknown device."
    @spec deny(db(), String.t()) :: :ok
    def deny(db \\ Tightbeam.DB, device_id) do
      transaction!(db, fn txn ->
        must_get(txn, device_id)

        Txn.q(txn, "UPDATE devices SET status = 'denied', token = NULL WHERE deviceId = ?1", [
          device_id
        ])

        stamp_device_in_txn(txn, device_id, now())

        :ok
      end)
    end
  end

  @doc false
  def deny_with_firehose(db, device_id, call) do
    transaction!(db, fn txn ->
      with :ok <- GrantAuth.authorize_in_txn(txn, call) do
        deny_in_txn(txn, device_id, call)
      end
    end)
  end

  defp deny_in_txn(txn, device_id, call) do
    must_get(txn, device_id)

    Txn.q(txn, "UPDATE devices SET status = 'denied', token = NULL WHERE deviceId = ?1", [
      device_id
    ])

    stamp_device_in_txn(txn, device_id, now())

    Publisher.maybe_accepted_in_txn(txn, call, %{device: firehose_device_in_txn(txn, device_id)})

    :ok
  end

  if @test_fixtures do
    @doc "Revoke a device's token (status unchanged — it re-pairs). Raises on unknown device."
    @spec revoke(db(), String.t()) :: :ok
    def revoke(db \\ Tightbeam.DB, device_id) do
      transaction!(db, fn txn ->
        must_get(txn, device_id)
        Txn.q(txn, "UPDATE devices SET token = NULL WHERE deviceId = ?1", [device_id])
        stamp_device_in_txn(txn, device_id, now())
        :ok
      end)
    end
  end

  @doc false
  def revoke_with_firehose(db, device_id, call) do
    transaction!(db, fn txn ->
      with :ok <- GrantAuth.authorize_in_txn(txn, call) do
        must_get(txn, device_id)
        Txn.q(txn, "UPDATE devices SET token = NULL WHERE deviceId = ?1", [device_id])
        stamp_device_in_txn(txn, device_id, now())

        Publisher.maybe_accepted_in_txn(txn, call, %{
          device: firehose_device_in_txn(txn, device_id)
        })

        :ok
      end
    end)
  end

  @doc "Monotonic public version for a device row."
  @spec version(db(), String.t()) :: integer() | nil
  def version(db \\ Tightbeam.DB, device_id) do
    case DB.query(db, "SELECT rowVersion FROM device_versions WHERE deviceId = ?1", [device_id]) do
      {:ok, [[version]]} -> version
      {:ok, []} -> nil
    end
  end

  @doc "User row by id, or nil. `is_admin` is effective: a removed user confers none."
  @spec user(db(), String.t()) :: user() | nil
  def user(db \\ Tightbeam.DB, user_id) do
    {:ok, rows} = DB.query(db, "SELECT #{@user_columns} FROM users WHERE userId = ?1", [user_id])

    case rows do
      [row] -> to_user(row)
      [] -> nil
    end
  end

  if @test_fixtures do
    @doc "Add a user. The shared cold-start insertion rule makes the first user admin."
    @spec add_user(db(), String.t(), boolean()) :: user()
    def add_user(db \\ Tightbeam.DB, user_id, is_admin) do
      transaction!(db, fn txn ->
        insert_user(txn, user_id, is_admin)

        user = must_get_user(txn, user_id)
        :ok = TerminalCredentialFailure.reconcile_admin_in_txn(txn, user_id)
        user
      end)
    end
  end

  @doc false
  # A removed user's id is not reusable: it returns the `user_removed`
  # refusal map and writes nothing.
  def add_user_with_firehose(db, user_id, is_admin, call) do
    transaction!(db, fn txn ->
      authorized = GrantAuth.authorize_in_txn(txn, call)

      cond do
        authorized != :ok ->
          authorized

        UserAdmin.removed_in_txn?(txn, user_id) ->
          UserAdmin.removed_refusal(user_id)

        true ->
          insert_user(txn, user_id, is_admin)
          user = StateResources.query_user(txn, user_id)
          :ok = TerminalCredentialFailure.reconcile_admin_in_txn(txn, user_id)
          Publisher.maybe_accepted_in_txn(txn, call, %{user: user})
          user
      end
    end)
  end

  @doc false
  def promote_user_with_firehose(db, user_id, call),
    do: promote_user_with_firehose(db, user_id, true, call)

  @doc false
  # A removed user cannot be promoted or demoted: it returns the
  # `user_removed` refusal map and writes nothing.
  def promote_user_with_firehose(db, user_id, is_admin, call) do
    transaction!(db, fn txn ->
      with :ok <- GrantAuth.authorize_in_txn(txn, call) do
        promote_in_txn(txn, user_id, is_admin, call)
      end
    end)
  end

  defp promote_in_txn(txn, user_id, is_admin, call) do
    user = must_get_user(txn, user_id)
    desired = !!is_admin

    cond do
      not is_nil(user.removed_at) ->
        UserAdmin.removed_refusal(user_id)

      user.stored_admin == desired ->
        :ok = TerminalCredentialFailure.reconcile_admin_in_txn(txn, user_id)
        Publisher.maybe_observed_accepted_in_txn(txn, call)
        %{user: StateResources.query_user(txn, user_id), changed: false}

      true ->
        Txn.q(txn, "UPDATE users SET isAdmin = ?2 WHERE userId = ?1", [
          user_id,
          if(desired, do: 1, else: 0)
        ])

        updated_at = System.system_time(:millisecond)
        AdminProjection.allocate_in_txn(txn, "users", user_id, updated_at)
        projection = StateResources.query_user(txn, user_id)
        :ok = TerminalCredentialFailure.reconcile_admin_in_txn(txn, user_id)
        Publisher.maybe_observed_accepted_in_txn(txn, call)
        class = if desired, do: "user.promoted", else: "user.demoted"
        Publisher.committed_in_txn(txn, class, projection, %{"userId" => user_id})
        %{user: projection, changed: true}
    end
  end

  if @test_fixtures do
    @doc "Set a user's admin bit (the promote-user verb's write). Raises on unknown user."
    @spec set_user_admin(db(), String.t(), boolean()) :: user()
    def set_user_admin(db \\ Tightbeam.DB, user_id, is_admin) do
      transaction!(db, fn txn ->
        must_get_user(txn, user_id)

        Txn.q(txn, "UPDATE users SET isAdmin = ?2 WHERE userId = ?1", [
          user_id,
          if(is_admin, do: 1, else: 0)
        ])

        user = must_get_user(txn, user_id)
        :ok = TerminalCredentialFailure.reconcile_admin_in_txn(txn, user_id)
        user
      end)
    end
  end

  @doc "Pending devices, oldest first (the approval queue)."
  @spec list_pending(db()) :: [device()]
  def list_pending(db \\ Tightbeam.DB) do
    {:ok, rows} =
      DB.query(db, select_device_sql() <> " WHERE d.status = 'pending' ORDER BY d.createdAt")

    Enum.map(rows, &to_device/1)
  end

  @doc "Count of users with at least one allowlisted device."
  @spec user_count(db()) :: non_neg_integer()
  def user_count(db \\ Tightbeam.DB) do
    {:ok, [[count]]} =
      DB.query(db, "SELECT COUNT(DISTINCT userId) FROM devices WHERE status = 'allowlisted'")

    count
  end

  defp select_device_sql do
    """
    SELECT d.deviceId, d.userId, d.claimedName, d.status, d.token, d.platform,
           d.model, d.createdAt, u.isAdmin, u.removedAt
    FROM devices d JOIN users u ON u.userId = d.userId
    """
  end

  defp select_device(txn, where, params) do
    Txn.q(txn, select_device_sql() <> " WHERE #{where}", params)
  end

  defp must_get(txn, device_id) do
    case select_device(txn, "d.deviceId = ?1", [device_id]) do
      [row] -> to_device(row)
      [] -> raise ArgumentError, "unknown device: #{device_id}"
    end
  end

  @doc false
  def detail_in_txn(%Txn{} = txn, device_id) do
    device = select_device(txn, "d.deviceId = ?1", [device_id]) |> one_device_or_nil()

    row_version =
      case Txn.q(txn, "SELECT rowVersion FROM device_versions WHERE deviceId = ?1", [device_id]) do
        [[version]] -> version
        [] -> nil
      end

    case device do
      nil -> nil
      device -> Map.put(device, :row_version, row_version || device.created_at)
    end
  end

  defp firehose_device_in_txn(txn, device_id) do
    device = must_get(txn, device_id)

    [[row_version]] =
      Txn.q(txn, "SELECT rowVersion FROM device_versions WHERE deviceId = ?1", [device_id])

    Map.put(device, :row_version, row_version)
  end

  defp one_device_or_nil([row]), do: to_device(row)
  defp one_device_or_nil([]), do: nil

  defp stamp_device_in_txn(txn, device_id, proposed) do
    Txn.q(
      txn,
      """
      INSERT INTO device_versions (deviceId, rowVersion) VALUES (?1, ?2)
      ON CONFLICT(deviceId) DO UPDATE
      SET rowVersion = MAX(excluded.rowVersion, device_versions.rowVersion + 1)
      """,
      [device_id, proposed]
    )
  end

  defp to_device([
         device_id,
         user_id,
         claimed_name,
         status,
         token,
         platform,
         model,
         created_at,
         is_admin,
         removed_at
       ]) do
    %{
      device_id: device_id,
      user_id: user_id,
      claimed_name: claimed_name,
      status: status,
      is_admin: is_admin == 1 and is_nil(removed_at),
      user_removed: not is_nil(removed_at),
      token: token,
      platform: platform,
      model: model,
      created_at: created_at
    }
  end

  if @test_fixtures do
    defp ensure_user(txn, user_id) do
      case Txn.q(txn, "SELECT userId FROM users WHERE userId = ?1", [user_id]) do
        [] ->
          insert_user(txn, user_id, false)

        [_] ->
          :ok
      end
    end
  end

  defp insert_user(txn, user_id, requested_admin) do
    created_at = now()

    Txn.q(
      txn,
      """
      INSERT INTO users (userId, isAdmin, createdAt)
      VALUES (
        ?1,
        CASE WHEN (SELECT COUNT(*) FROM users) = 0 THEN 1 ELSE ?2 END,
        ?3
      )
      """,
      [user_id, if(requested_admin, do: 1, else: 0), created_at]
    )

    AdminProjection.allocate_in_txn(txn, "users", user_id, created_at)
  end

  defp must_get_user(txn, user_id) do
    case Txn.q(txn, "SELECT #{@user_columns} FROM users WHERE userId = ?1", [user_id]) do
      [row] -> to_user(row)
      [] -> raise ArgumentError, "unknown user: #{user_id}"
    end
  end

  defp to_user([user_id, is_admin, created_at, removed_at, removed_by]) do
    %{
      user_id: user_id,
      is_admin: is_admin == 1 and is_nil(removed_at),
      stored_admin: is_admin == 1,
      created_at: created_at,
      removed_at: removed_at,
      removed_by: removed_by
    }
  end

  if @test_fixtures do
    defp mint_token do
      "tbt_" <> (:crypto.strong_rand_bytes(24) |> Base.url_encode64(padding: false))
    end
  end

  defp transaction!(db, fun) do
    case DB.transaction(db, fun) do
      {:ok, result} -> result
      {:error, error} -> raise error
    end
  end

  defp now, do: System.system_time(:millisecond)
end
