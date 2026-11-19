defmodule Tightbeam.DeviceLifecycle do
  @moduledoc """
  Device lifecycle, stage 1 (spec stage1-v8): one-time-code pairing and full-lockout
  recovery. It replaces core fix (A)'s pairing freeze and escape hatch.

  - **Pairing codes** (S2.1): `TB-XXXX-XXXX-XXXX`, 60 bits of Crockford base 32, issued
    from an admin-paired device for a target user, single use, valid 10 minutes (60
    for a recovery or root code). Only an Argon2id verifier (S0.3) is stored; the code
    goes back to the requesting connection alone, never into a transcript, event,
    log, projection or store. At most 5 codes are outstanding gateway-wide.
  - **Recovery secrets** (S1.1): `TBR-XXXXX-XXXXX-XXXXX-XXXXX`, 100 bits, one per
    admin, enrolled from an admin-paired device and stored only as a verifier. The
    offline ceremony itself (S1.2, S1.5) is the CLI's.
  - **Coded pairing** (S2.2): cheap admission first (shape; nothing outstanding; rate;
    a gateway-wide verification gate), then at most 5 Argon2id checks, then one
    transaction that uses the code and mints a token.
  - **Delivery by use** (S2.3): a minted token is undelivered until the device's first
    sign-in, which also consumes the user's recovery secret when the device was
    paired with a recovery code. An undelivered token is cleared at its deadline.

  Plaintext codes and secrets are returned to the calling process only, by message,
  so no dispatch result, audit row or change-feed notice can carry them.
  """

  require Logger
  import Bitwise

  alias Tightbeam.{DB, EventLog, GrantAuth, Native, Org, OwnerAlerts, PairingAdmission, Wakes}
  alias Tightbeam.DB.Txn

  @crockford ~c"0123456789ABCDEFGHJKMNPQRSTVWXYZ"
  @code_ttl_ms 600_000
  @delivery_deadline_ms 600_000
  @max_outstanding 5
  @max_name_length 64

  @code_shape ~r/\A(?<name>.*\S)\s+(?<code>TB-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4})\z/iu

  @code_required_message "Ask the owner to send `/tightbeam approve-device` from a paired " <>
                           "device, then enter `<name> <code>` as this device's name."
  @code_invalid_message "The pairing code was not accepted: it may be mistyped, used or " <>
                          "expired. Ask the owner for a new code."
  @rate_limited_message "Too many pairing attempts; try again shortly."
  @name_too_long_message "The device name is too long: keep the name before the code to " <>
                           "46 characters or fewer, then enter `<name> <code>` again."

  ## Schema

  @shape "device-lifecycle-stage1-v1-0114"

  @migration_stamp_ddl """
  CREATE TABLE device_lifecycle_migration (
    id        INTEGER PRIMARY KEY CHECK (id = 0),
    shape     TEXT NOT NULL CHECK (shape = '#{@shape}'),
    appliedAt INTEGER NOT NULL CHECK (appliedAt >= 0)
  )
  """

  @recovery_secrets_ddl """
  CREATE TABLE recovery_secrets (
    userId     TEXT PRIMARY KEY,
    verifier   BLOB NOT NULL CHECK (length(verifier) = 32),
    salt       BLOB NOT NULL CHECK (length(salt) = 16),
    enrolledAt INTEGER NOT NULL CHECK (enrolledAt >= 0),
    consumedAt INTEGER
  )
  """

  @pairing_codes_ddl """
  CREATE TABLE pairing_codes (
    codeId          TEXT PRIMARY KEY CHECK (length(codeId) = 19 AND substr(codeId, 1, 3) = 'pc_'),
    verifier        BLOB NOT NULL CHECK (length(verifier) = 32),
    salt            BLOB NOT NULL CHECK (length(salt) = 16),
    userId          TEXT NOT NULL,
    issuingDeviceId TEXT,
    recovery        INTEGER NOT NULL CHECK (recovery IN (0, 1)),
    issuedAt        INTEGER NOT NULL CHECK (issuedAt >= 0),
    expiresAt       INTEGER NOT NULL CHECK (expiresAt > issuedAt),
    usedAt          INTEGER,
    usedByDeviceId  TEXT,
    invalidatedAt   INTEGER,
    CHECK ((usedAt IS NULL) = (usedByDeviceId IS NULL))
  )
  """

  @pairing_codes_outstanding_ddl """
  CREATE INDEX pairing_codes_outstanding ON pairing_codes (expiresAt)
    WHERE usedAt IS NULL AND invalidatedAt IS NULL
  """

  # Recoveries and root-shell actions the CLI records while the gateway is stopped;
  # the gateway alerts each once at its next start (S1.3, S1.5 (6)).
  @host_actions_ddl """
  CREATE TABLE gateway_host_actions (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    kind      TEXT NOT NULL CHECK (kind IN ('admin-recovered', 'root-recovery-enroll', 'root-pairing-code')),
    userId    TEXT NOT NULL,
    codeId    TEXT,
    account   TEXT,
    tty       TEXT,
    at        INTEGER NOT NULL CHECK (at >= 0),
    alertedAt INTEGER
  )
  """

  @tables [
    {"recovery_secrets", @recovery_secrets_ddl},
    {"pairing_codes", @pairing_codes_ddl},
    {"gateway_host_actions", @host_actions_ddl}
  ]

  @indexes [{"pairing_codes_outstanding", @pairing_codes_outstanding_ddl}]

  @device_columns [
    # Delivered unless a coded pairing minted the token (S2.3): that is the only
    # writer of 0, and it always sets the deadline.
    {"tokenDelivered", "INTEGER", "tokenDelivered INTEGER NOT NULL DEFAULT 1"},
    {"deliveryDeadline", "INTEGER", "deliveryDeadline INTEGER"},
    {"tokenGeneration", "INTEGER", "tokenGeneration INTEGER NOT NULL DEFAULT 0"},
    {"pairedCodeId", "TEXT", "pairedCodeId TEXT"}
  ]

  @doc "The stage 1 schema shape this module creates and validates."
  def shape, do: @shape

  @doc "Add the S5 records once, over any current schema, or validate them."
  @spec ensure_schema(DB.server()) :: :ok
  def ensure_schema(db \\ DB) do
    case DB.migration_transaction(db, :device_lifecycle_stage1, [], [], &migrate_in_txn/1) do
      {:ok, :ok} -> :ok
      {:error, error} -> raise error
    end
  end

  defp migrate_in_txn(txn) do
    case Txn.q(
           txn,
           "SELECT sql FROM sqlite_master WHERE type='table' AND name='device_lifecycle_migration'"
         ) do
      [] ->
        Enum.each(@device_columns, fn {column, _type, definition} ->
          if column_info(txn, column),
            do: shape_error("incompatible_device_lifecycle_unstamped_column: #{column}")

          :ok = Txn.exec(txn, "ALTER TABLE devices ADD COLUMN #{definition}")
        end)

        # S5: every token that exists at installation is delivered (the default).

        Enum.each(@tables ++ @indexes, fn {name, ddl} ->
          if Txn.q(txn, "SELECT 1 FROM sqlite_master WHERE name = ?1", [name]) != [],
            do: shape_error("incompatible_device_lifecycle_unstamped_object: #{name}")

          :ok = Txn.exec(txn, ddl)
        end)

        :ok = Txn.exec(txn, @migration_stamp_ddl)

        Txn.q(
          txn,
          "INSERT INTO device_lifecycle_migration (id, shape, appliedAt) VALUES (0, ?1, ?2)",
          [@shape, now()]
        )

        validate!(txn)

      [[sql]] ->
        unless normalize(sql) == normalize(@migration_stamp_ddl),
          do: shape_error("incompatible_device_lifecycle_migration_ddl")

        case Txn.q(txn, "SELECT id, shape FROM device_lifecycle_migration") do
          [[0, @shape]] -> validate!(txn)
          rows -> shape_error("incompatible_device_lifecycle_stamp: #{inspect(rows)}")
        end
    end
  end

  defp validate!(txn) do
    Enum.each(@device_columns, fn {column, type, _} ->
      case column_info(txn, column) do
        [_cid, ^column, ^type | _] -> :ok
        other -> shape_error("incompatible_device_lifecycle_column: #{column} #{inspect(other)}")
      end
    end)

    Enum.each(@tables ++ @indexes, fn {name, ddl} ->
      case Txn.q(txn, "SELECT sql FROM sqlite_master WHERE name = ?1", [name]) do
        [[sql]] ->
          unless normalize(sql) == normalize(ddl),
            do: shape_error("incompatible_device_lifecycle_object: #{name}")

        rows ->
          shape_error("incompatible_device_lifecycle_object: #{name} #{inspect(rows)}")
      end
    end)

    :ok
  end

  defp column_info(txn, column),
    do: Enum.find(Txn.q(txn, "PRAGMA table_info(devices)"), &(Enum.at(&1, 1) == column))

  defp normalize(sql),
    do:
      sql
      |> String.replace("\"", "")
      |> String.replace(~r/\s+/, " ")
      |> String.trim()
      |> String.trim_trailing(";")

  defp shape_error(message), do: raise(Tightbeam.Schema.ShapeError, message: message)

  ## Codes and secrets

  @doc "A fresh pairing code, `TB-XXXX-XXXX-XXXX` (60 bits)."
  @spec new_code() :: String.t()
  def new_code do
    <<a::binary-4, b::binary-4, c::binary-4>> = crockford(12)
    "TB-#{a}-#{b}-#{c}"
  end

  @doc "A fresh recovery secret, `TBR-XXXXX-XXXXX-XXXXX-XXXXX` (100 bits)."
  @spec new_secret() :: String.t()
  def new_secret do
    <<a::binary-5, b::binary-5, c::binary-5, d::binary-5>> = crockford(20)
    "TBR-#{a}-#{b}-#{c}-#{d}"
  end

  # Five random bits per character, drawn without modulo bias.
  defp crockford(count) do
    bits = :crypto.strong_rand_bytes(div(count * 5 + 7, 8))
    <<value::size(count * 5), _::bitstring>> = bits

    for shift <- (count - 1)..0//-1,
        into: "",
        do: <<Enum.at(@crockford, value >>> (shift * 5) &&& 31)>>
  end

  defp code_id, do: "pc_" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)

  @doc false
  # The canonical form a verifier is computed over: upper case, as shown.
  def canonical(text), do: String.upcase(String.trim(text))

  defp verifier(text, salt), do: Native.argon2id(canonical(text), salt)

  ## S2.1 issuing a code

  @doc """
  Issue a pairing code for `user_id` from an admin-paired device call. Returns the
  public record; the plaintext is sent to the calling process as
  `{:tightbeam_ephemeral, text}`, never returned. A refusal changes nothing.
  """
  @spec issue_code(DB.server(), map(), String.t() | nil) :: map()
  def issue_code(db, call, target_user) do
    code = new_code()
    salt = :crypto.strong_rand_bytes(16)
    verifier = verifier(code, salt)
    id = code_id()

    {:ok, result} =
      DB.transaction(db, fn txn ->
        with :ok <- GrantAuth.authorize_in_txn(txn, call),
             %{user_id: issuer} <- GrantAuth.device_user_in_txn(txn, call),
             target = target_user || issuer,
             :ok <- active_user_in_txn(txn, target) do
          issued_at = now()
          expires_at = issued_at + @code_ttl_ms

          insert_code_in_txn(
            txn,
            id,
            verifier,
            salt,
            target,
            GrantAuth.auth_device_id(call),
            false,
            issued_at,
            expires_at
          )

          EventLog.lifecycle_in_txn(
            txn,
            "pairing_code_issued",
            id,
            JSON.encode!(%{codeId: id, userId: target, expiresAt: expires_at, recovery: false})
          )

          # A transactional verb publishes its acceptance in its own transaction; the
          # notice names the verb only, never the code.
          Tightbeam.Firehose.Publisher.maybe_observed_accepted_in_txn(txn, call)

          {:issued, %{code_id: id, user_id: target, expires_at: expires_at}}
        end
      end)

    case result do
      {:issued, issued} ->
        send(
          self(),
          {:tightbeam_ephemeral,
           "Pairing code #{code} for #{issued.user_id}, valid until #{clock(issued.expires_at)}. " <>
             "On the new device, enter its name, a space, then this code. It works once, " <>
             "and is shown only here."}
        )

        Map.put(
          issued,
          :message,
          "pairing code #{issued.code_id} issued for #{issued.user_id}, expires #{iso(issued.expires_at)}"
        )

      refusal ->
        refusal
    end
  end

  # Store a code, then keep at most 5 outstanding by invalidating the oldest (S0.3).
  # Private: callers reach it only through the gated `issue_code/3` (review B1).
  defp insert_code_in_txn(txn, id, verifier, salt, user, device, recovery?, issued_at, expires_at) do
    Txn.q(
      txn,
      """
      INSERT INTO pairing_codes
        (codeId, verifier, salt, userId, issuingDeviceId, recovery, issuedAt, expiresAt)
      VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
      """,
      [
        id,
        {:blob, verifier},
        {:blob, salt},
        user,
        device,
        if(recovery?, do: 1, else: 0),
        issued_at,
        expires_at
      ]
    )

    outstanding =
      Txn.q(
        txn,
        """
        SELECT codeId FROM pairing_codes
        WHERE usedAt IS NULL AND invalidatedAt IS NULL AND expiresAt > ?1
        ORDER BY issuedAt DESC, codeId DESC
        """,
        [issued_at]
      )

    outstanding
    |> Enum.drop(@max_outstanding)
    |> Enum.each(fn [old] ->
      Txn.q(txn, "UPDATE pairing_codes SET invalidatedAt = ?2 WHERE codeId = ?1", [old, issued_at])

      EventLog.lifecycle_in_txn(
        txn,
        "pairing_code_invalidated",
        old,
        JSON.encode!(%{codeId: old, reason: "limit"})
      )
    end)

    :ok
  end

  defp active_user_in_txn(txn, user_id) do
    case Txn.q(txn, "SELECT removedAt FROM users WHERE userId = ?1", [user_id]) do
      [[nil]] -> :ok
      [[_removed]] -> Tightbeam.UserAdmin.removed_refusal(user_id)
      [] -> %{code: "user_not_found", message: "no user #{user_id}"}
    end
  end

  ## S1.1 enrolment

  @doc """
  Enrol a new recovery secret for the calling admin device's user, invalidating any
  previous one. The plaintext goes to the calling process as
  `{:tightbeam_ephemeral, text}`. Records an event and raises one owner alert.
  """
  @spec enroll(DB.server(), map()) :: map()
  def enroll(db, call) do
    secret = new_secret()
    salt = :crypto.strong_rand_bytes(16)
    verifier = verifier(secret, salt)

    {:ok, result} =
      DB.transaction(db, fn txn ->
        with :ok <- GrantAuth.authorize_in_txn(txn, call),
             %{user_id: user} <- GrantAuth.device_user_in_txn(txn, call) do
          at = now()
          enroll_in_txn(txn, user, verifier, salt, at)
          {:enrolled, %{user_id: user, enrolled_at: at}}
        end
      end)

    case result do
      {:enrolled, enrolled} ->
        send(
          self(),
          {:tightbeam_ephemeral,
           "Recovery secret for #{enrolled.user_id}: #{secret}. Write it down on paper now " <>
             "and keep it offline. It is shown only this once, here. With the gateway " <>
             "stopped, `tightbeam recover-admin --user #{enrolled.user_id}` on the gateway " <>
             "host takes it and gives you a pairing code for a new device."}
        )

        Map.put(
          enrolled,
          :message,
          "recovery secret enrolled for #{enrolled.user_id} at #{iso(enrolled.enrolled_at)}"
        )

      refusal ->
        refusal
    end
  end

  # Private: callers reach it only through the gated `enroll/2` (review B1).
  defp enroll_in_txn(txn, user, verifier, salt, at) do
    Txn.q(
      txn,
      """
      INSERT INTO recovery_secrets (userId, verifier, salt, enrolledAt, consumedAt)
      VALUES (?1, ?2, ?3, ?4, NULL)
      ON CONFLICT(userId) DO UPDATE SET verifier = excluded.verifier, salt = excluded.salt,
        enrolledAt = excluded.enrolledAt, consumedAt = NULL
      """,
      [user, {:blob, verifier}, {:blob, salt}, at]
    )

    EventLog.lifecycle_in_txn(
      txn,
      "recovery_secret_enrolled",
      user,
      JSON.encode!(%{userId: user, enrolledAt: at})
    )

    alert_in_txn(
      txn,
      "recovery-enrolled",
      "recovery-enrolled:#{user}:#{at}",
      "Recovery secret (re)enrolled",
      "A recovery secret was (re)enrolled for #{user} at #{iso(at)}. If you did not do this, " <>
        "enrol a new one from your paired device now and tell the platform owner."
    )
  end

  ## S2.2 coded pairing

  @doc """
  Decide one `pair_request` (S2.2). Returns `{:paired, device}` or
  `{:refused, reason, message}`.
  """
  @spec pair(DB.server(), map(), keyword()) ::
          {:paired, map()} | {:refused, String.t(), String.t()}
  def pair(db, input, opts \\ []) do
    claimed = to_string(Map.get(input, :claimed_name) || "")

    case Regex.named_captures(@code_shape, String.trim(claimed)) do
      nil ->
        {:refused, "pairing_code_required", @code_required_message}

      %{"name" => name, "code" => code} ->
        if String.length(String.trim(claimed)) > @max_name_length do
          {:refused, "pairing_code_invalid", @name_too_long_message}
        else
          case outstanding(db) do
            # A database too busy for the cheap check refuses like the rate limit.
            :busy -> {:refused, "rate_limited", @rate_limited_message}
            [] -> {:refused, "pairing_code_invalid", @code_invalid_message}
            _some -> admit_and_redeem(db, input, name, code, opts)
          end
        end
    end
  end

  defp admit_and_redeem(db, input, name, code, opts) do
    admission = Keyword.get(opts, :admission, PairingAdmission)

    case PairingAdmission.run(admission, fn -> match(db, code) end) do
      {:ok, nil} -> {:refused, "pairing_code_invalid", @code_invalid_message}
      {:ok, code_id} -> redeem(db, code_id, input, String.trim(name))
      {:error, :rate_limited} -> {:refused, "rate_limited", @rate_limited_message}
    end
  end

  defp outstanding(db) do
    case DB.query(
           db,
           """
           SELECT codeId, verifier, salt FROM pairing_codes
           WHERE usedAt IS NULL AND invalidatedAt IS NULL AND expiresAt > ?1
           ORDER BY issuedAt LIMIT #{@max_outstanding}
           """,
           [now()]
         ) do
      {:ok, rows} -> rows
      {:error, _overloaded_or_failed} -> :busy
    end
  end

  # At most 5 Argon2id checks, every one computed so timing does not reveal a match.
  defp match(db, code) do
    candidate = canonical(code)

    case outstanding(db) do
      :busy -> []
      rows -> rows
    end
    |> Enum.reduce(nil, fn [id, stored, salt], found ->
      if :crypto.hash_equals(Native.argon2id(candidate, salt), stored) and is_nil(found),
        do: id,
        else: found
    end)
  end

  defp redeem(db, code_id, input, name) do
    device_id = Map.fetch!(input, :device_id)

    {:ok, result} =
      DB.transaction(db, fn txn ->
        now = now()

        with [[user, recovery]] <-
               Txn.q(
                 txn,
                 """
                 SELECT c.userId, c.recovery FROM pairing_codes c JOIN users u ON u.userId = c.userId
                 WHERE c.codeId = ?1 AND c.usedAt IS NULL AND c.invalidatedAt IS NULL
                   AND c.expiresAt > ?2 AND u.removedAt IS NULL
                 """,
                 [code_id, now]
               ),
             false <- holds_token_in_txn?(txn, device_id) do
          token = mint_token()
          deadline = now + @delivery_deadline_ms

          case Txn.q(txn, "SELECT 1 FROM devices WHERE deviceId = ?1", [device_id]) do
            [] ->
              Txn.q(
                txn,
                """
                INSERT INTO devices
                  (deviceId, userId, claimedName, status, token, platform, model, createdAt,
                   tokenCollected, tokenDelivered, deliveryDeadline, tokenGeneration, pairedCodeId)
                VALUES (?1, ?2, ?3, 'allowlisted', ?4, ?5, ?6, ?7, 1, 0, ?8, 1, ?9)
                """,
                [
                  device_id,
                  user,
                  name,
                  token,
                  Map.get(input, :platform),
                  Map.get(input, :model),
                  now,
                  deadline,
                  code_id
                ]
              )

            [_] ->
              Txn.q(
                txn,
                """
                UPDATE devices SET userId = ?2, claimedName = ?3, status = 'allowlisted', token = ?4,
                  platform = COALESCE(?5, platform), model = COALESCE(?6, model),
                  tokenCollected = 1, tokenDelivered = 0, deliveryDeadline = ?7,
                  tokenGeneration = tokenGeneration + 1, pairedCodeId = ?8
                WHERE deviceId = ?1
                """,
                [
                  device_id,
                  user,
                  name,
                  token,
                  Map.get(input, :platform),
                  Map.get(input, :model),
                  deadline,
                  code_id
                ]
              )
          end

          Txn.q(
            txn,
            "INSERT INTO device_versions (deviceId, rowVersion) VALUES (?1, ?2) ON CONFLICT(deviceId) DO UPDATE SET rowVersion = MAX(excluded.rowVersion, device_versions.rowVersion + 1)",
            [device_id, now]
          )

          Txn.q(
            txn,
            "UPDATE pairing_codes SET usedAt = ?2, usedByDeviceId = ?3 WHERE codeId = ?1 AND usedAt IS NULL",
            [code_id, now, device_id]
          )

          if Txn.changes(txn) != 1, do: raise(DB.Error, message: "pairing code lost its use CAS")

          EventLog.lifecycle_in_txn(
            txn,
            "pairing_code_redeemed",
            code_id,
            JSON.encode!(%{
              codeId: code_id,
              deviceId: device_id,
              userId: user,
              recovery: recovery == 1,
              deliveryDeadline: deadline
            })
          )

          Tightbeam.Firehose.Publisher.committed_in_txn(
            txn,
            "device.approved",
            Tightbeam.StateResources.device(Tightbeam.Devices.detail_in_txn(txn, device_id)),
            %{"deviceId" => device_id}
          )

          {:paired, %{device_id: device_id, user_id: user, token: token, deadline: deadline}}
        else
          true ->
            {:refused, "already_paired",
             "This device is already paired; its token keeps working."}

          _ ->
            {:refused, "pairing_code_invalid", @code_invalid_message}
        end
      end)

    result
  end

  defp holds_token_in_txn?(txn, device_id) do
    Txn.q(
      txn,
      "SELECT 1 FROM devices WHERE deviceId = ?1 AND status = 'allowlisted' AND token IS NOT NULL",
      [device_id]
    ) == [[1]]
  end

  ## S2.3 delivery by use

  @doc """
  The device's sign-in with `token` (S2.3). An undelivered token is marked delivered
  in time, consuming the user's recovery secret when it was paired with a recovery
  code; past its deadline it is cleared instead. Returns `:ok` or `:expired`.
  """
  @spec sign_in(DB.server(), String.t()) :: :ok | :expired
  def sign_in(db, token) do
    {:ok, result} =
      DB.transaction(db, fn txn ->
        case Txn.q(
               txn,
               "SELECT deviceId, userId, tokenDelivered, deliveryDeadline, tokenGeneration, pairedCodeId FROM devices WHERE token = ?1 AND status = 'allowlisted'",
               [token]
             ) do
          [[_device, _user, 1, _deadline, _generation, _code]] ->
            :ok

          [[device, user, 0, deadline, generation, code_id]] ->
            if is_integer(deadline) and deadline > now() do
              Txn.q(
                txn,
                "UPDATE devices SET tokenDelivered = 1 WHERE deviceId = ?1 AND tokenGeneration = ?2 AND tokenDelivered = 0 AND token = ?3",
                [device, generation, token]
              )

              if Txn.changes(txn) == 1 do
                consume_recovery_secret_in_txn(txn, user, code_id)

                EventLog.lifecycle_in_txn(
                  txn,
                  "pairing_delivered",
                  device,
                  JSON.encode!(%{deviceId: device, userId: user, tokenGeneration: generation})
                )
              end

              :ok
            else
              expire_in_txn(txn, device, generation)
              :expired
            end

          [] ->
            :ok
        end
      end)

    result
  end

  defp consume_recovery_secret_in_txn(txn, user, code_id) when is_binary(code_id) do
    if Txn.q(txn, "SELECT recovery FROM pairing_codes WHERE codeId = ?1", [code_id]) == [[1]] do
      Txn.q(
        txn,
        "UPDATE recovery_secrets SET consumedAt = ?2 WHERE userId = ?1 AND consumedAt IS NULL",
        [user, now()]
      )

      if Txn.changes(txn) == 1 do
        EventLog.lifecycle_in_txn(
          txn,
          "recovery_secret_consumed",
          user,
          JSON.encode!(%{userId: user, codeId: code_id})
        )
      end
    end

    :ok
  end

  defp consume_recovery_secret_in_txn(_txn, _user, _code_id), do: :ok

  defp expire_in_txn(txn, device, generation) do
    Txn.q(
      txn,
      "UPDATE devices SET token = NULL WHERE deviceId = ?1 AND tokenGeneration = ?2 AND tokenDelivered = 0",
      [device, generation]
    )

    if Txn.changes(txn) == 1 do
      EventLog.lifecycle_in_txn(
        txn,
        "pairing_delivery_failed",
        device,
        JSON.encode!(%{deviceId: device, tokenGeneration: generation})
      )
    end
  end

  @doc "Clear every undelivered token past its deadline (S2.3). Returns the count."
  @spec expire_due(DB.server(), integer()) :: non_neg_integer()
  def expire_due(db, at \\ now()) do
    {:ok, count} =
      DB.transaction(db, fn txn ->
        txn
        |> Txn.q(
          "SELECT deviceId, tokenGeneration FROM devices WHERE tokenDelivered = 0 AND token IS NOT NULL AND deliveryDeadline <= ?1",
          [at]
        )
        |> Enum.map(fn [device, generation] -> expire_in_txn(txn, device, generation) end)
        |> length()
      end)

    count
  end

  @doc "The earliest pending delivery deadline, or nil."
  @spec next_deadline(DB.server()) :: integer() | nil
  def next_deadline(db) do
    {:ok, [[value]]} =
      DB.query(
        db,
        "SELECT MIN(deliveryDeadline) FROM devices WHERE tokenDelivered = 0 AND token IS NOT NULL"
      )

    value
  end

  ## Boot (S0.2, S1.3, S1.5 (6))

  @doc """
  At boot: record and alert an ignored unfreeze file, and alert every recovery or
  root-shell action the CLI recorded while the gateway was stopped.
  """
  @spec observe_at_boot(DB.server(), String.t()) :: :ok
  def observe_at_boot(db, unfreeze_path) do
    {:ok, :ok} =
      DB.transaction(db, fn txn ->
        if File.exists?(unfreeze_path) or match?({:ok, _}, File.lstat(unfreeze_path)) do
          at = now()

          EventLog.lifecycle_in_txn(
            txn,
            "pairing_unfreeze_ignored",
            unfreeze_path,
            JSON.encode!(%{at: at})
          )

          alert_in_txn(
            txn,
            "pairing-unfreeze-ignored",
            "pairing-unfreeze-ignored:#{at}",
            "Old pairing-unfreeze file ignored",
            "The old pairing-unfreeze file no longer has any effect. Remove it with `sudo rm`."
          )
        end

        txn
        |> Txn.q(
          "SELECT id, kind, userId, codeId, account, tty, at FROM gateway_host_actions WHERE alertedAt IS NULL ORDER BY id"
        )
        |> Enum.each(fn [id, kind, user, code_id, account, tty, at] ->
          text = host_action_text(kind, user, code_id, account, tty, at)
          alert_in_txn(txn, kind, "host-action:#{id}", host_action_title(kind), text)
          wake_admin_mains_in_txn(txn, text, at)
          Txn.q(txn, "UPDATE gateway_host_actions SET alertedAt = ?2 WHERE id = ?1", [id, now()])
        end)

        :ok
      end)

    :ok
  rescue
    error ->
      Logger.error("device lifecycle boot observation failed: #{Exception.message(error)}")
      :ok
  end

  defp host_action_title("admin-recovered"), do: "Admin devices recovered"
  defp host_action_title(_root), do: "Root shell acted on device access"

  defp host_action_text("admin-recovered", user, _code, _account, _tty, at),
    do: "Admin devices of #{user} were recovered at #{iso(at)} from the gateway host."

  defp host_action_text(kind, user, _code, account, tty, at) do
    what =
      if kind == "root-recovery-enroll",
        do: "enrolled a recovery secret",
        else: "issued a pairing code"

    "A root shell on the gateway host #{what} for #{user} at #{iso(at)} " <>
      "(by #{account || "unknown"} on #{tty || "unknown"}). If that was not you, someone " <>
      "has root-level access; tell the platform owner."
  end

  defp wake_admin_mains_in_txn(txn, text, at) do
    txn
    |> Txn.q("SELECT userId FROM users WHERE isAdmin = 1 AND removedAt IS NULL ORDER BY userId")
    |> Enum.each(fn [user] ->
      main = Org.personal_session_key(user)

      if Txn.q(txn, "SELECT 1 FROM sessions WHERE sessionKey = ?1", [main]) == [[1]] do
        Wakes.schedule_in_txn(txn, %{
          session_key: main,
          origin: "process:tightbeam",
          prompt: text,
          due_at: max(at, now()),
          class: "blocker",
          sender_scheduled: true
        })
      end
    end)
  end

  defp alert_in_txn(txn, kind, dedupe_key, title, body),
    do: OwnerAlerts.device_lifecycle_in_txn(txn, kind, dedupe_key, title, body)

  ## helpers

  defp mint_token, do: "tbt_" <> Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)

  defp iso(ms) do
    case DateTime.from_unix(ms, :millisecond) do
      {:ok, at} -> DateTime.to_iso8601(at)
      _ -> Integer.to_string(ms)
    end
  end

  defp clock(ms), do: OwnerAlerts.format_local(ms)

  defp now, do: System.system_time(:millisecond)
end
