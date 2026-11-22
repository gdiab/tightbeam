defmodule Tightbeam.TestDevices do
  @moduledoc """
  Paired-device fixtures for tests whose subject is not pairing.

  Core fix (A) freezes pairing: no `pair_request` issues a token, the cold start
  included. Tests that only need "a paired device" therefore insert one directly,
  with the outcome pairing produced before the fix:

  - the first device of an empty organization becomes an allowlisted device of a
    new admin user, with a token;
  - a further device of a new claimed user is pending, without a token;
  - a known allowlisted device gets a fresh token.

  Every token written here counts as collected, as every pre-existing token does
  after the fix's migration. Pairing itself is tested through `Tightbeam.Devices`.
  """

  alias Tightbeam.{DB, Devices}

  # A database from before core fix (A) has no tokenCollected column; the fix's
  # own migration later marks every token it finds collected.
  defp collected?(db) do
    {:ok, [[n]]} =
      DB.query(
        db,
        "SELECT COUNT(*) FROM pragma_table_info('devices') WHERE name='tokenCollected'"
      )

    n == 1
  end

  defp collected_set(db), do: if(collected?(db), do: ", tokenCollected = 1", else: "")
  defp collected_column(db), do: if(collected?(db), do: ", tokenCollected", else: "")
  defp collected_value(db), do: if(collected?(db), do: ", 1", else: "")

  @doc "Emulate pre-fix pairing for a fixture: see the moduledoc."
  @spec pair(GenServer.server(), map()) :: {:paired, map()} | {:pending, map()} | :denied
  def pair(db, input) do
    device_id = Map.fetch!(input, :device_id)

    case Devices.by_id(db, device_id) do
      %{status: "denied"} ->
        :denied

      %{status: "pending"} = device ->
        {:pending, device}

      %{status: "allowlisted"} ->
        :ok =
          exec(db, "UPDATE devices SET token = ?2#{collected_set(db)} WHERE deviceId = ?1", [
            device_id,
            mint_token()
          ])

        {:paired, Devices.by_id(db, device_id)}

      nil ->
        user_id = slug(Map.fetch!(input, :claimed_name))
        {:ok, [[users]]} = DB.query(db, "SELECT COUNT(*) FROM users")
        first? = users == 0

        ensure_user(db, user_id, first?)

        status = if first?, do: "allowlisted", else: "pending"
        token = if first?, do: fixture_token(device_id)

        :ok =
          exec(
            db,
            """
            INSERT INTO devices
              (deviceId, userId, claimedName, status, token, platform, model, createdAt
               #{collected_column(db)})
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8 #{collected_value(db)})
            """,
            [
              device_id,
              user_id,
              Map.fetch!(input, :claimed_name),
              status,
              token,
              Map.get(input, :platform),
              Map.get(input, :model),
              now()
            ]
          )

        :ok =
          exec(
            db,
            "INSERT OR REPLACE INTO device_versions (deviceId, rowVersion) VALUES (?1, ?2)",
            [device_id, now()]
          )

        device = Devices.by_id(db, device_id)
        if first?, do: {:paired, device}, else: {:pending, device}
    end
  end

  @doc """
  An allowlisted device with a token for `user_id`, creating the user (admin when
  `admin: true`, or when it is the organization's first user).
  """
  @spec paired!(GenServer.server(), String.t(), keyword()) :: map()
  def paired!(db, user_id, opts \\ []) do
    device_id = Keyword.get(opts, :device_id, "dev_" <> user_id)
    admin = Keyword.get(opts, :admin, false)

    ensure_user(db, user_id, admin)

    :ok =
      exec(
        db,
        """
        INSERT INTO devices
          (deviceId, userId, claimedName, status, token, platform, model, createdAt,
           tokenCollected)
        VALUES (?1, ?2, ?3, 'allowlisted', ?4, ?5, ?6, ?7, 1)
        """,
        [
          device_id,
          user_id,
          Keyword.get(opts, :claimed_name, user_id <> "'s phone"),
          fixture_token(device_id),
          Keyword.get(opts, :platform, "ios"),
          Keyword.get(opts, :model, "iPhone"),
          now()
        ]
      )

    :ok =
      exec(
        db,
        "INSERT OR REPLACE INTO device_versions (deviceId, rowVersion) VALUES (?1, ?2)",
        [device_id, now()]
      )

    Devices.by_id(db, device_id)
  end

  @doc """
  The transport fields of a call made on `device`'s authenticated connection,
  including the proof of its token (core fix (A), review B1).
  """
  @spec device_call(map(), map()) :: map()
  def device_call(device, call \\ %{}) do
    Map.merge(call, %{
      origin: "user:#{device.user_id}",
      principal: {:user, device.user_id},
      auth_class: "device",
      auth_device_id: device.device_id,
      auth_proof: Tightbeam.GrantAuth.proof(device.token)
    })
  end

  @doc """
  The token a fixture first mints for `device_id`. It is derived from the id so a
  test can name a device's credential proof (`proof/1`) without holding its row.
  """
  @spec fixture_token(String.t()) :: String.t()
  def fixture_token(device_id),
    do:
      "tbt_" <>
        String.slice(
          Base.url_encode64(:crypto.hash(:sha256, "fixture:" <> device_id), padding: false),
          0,
          32
        )

  @doc "The transport proof of a fixture device's first-minted token."
  @spec proof(String.t()) :: binary()
  def proof(device_id), do: Tightbeam.GrantAuth.proof(fixture_token(device_id))

  @doc """
  A path that passes every core fix (A) C6a check, for tests that lift the freeze:
  a regular file owned by uid 0 and gid 0, not writable by group or others, whose
  directory and that directory's parent are root-owned and not group- or
  other-writable.

  An existing system file is used when one passes. Otherwise, on a CI runner with
  passwordless sudo, one is built once with sudo in a temporary tree. Elsewhere the
  test fails, naming each candidate's failing check. Nothing here ever writes a
  host's real `/etc`.
  """
  @spec valid_unfreeze_file!() :: String.t()
  def valid_unfreeze_file! do
    candidates = ["/usr/bin/env", "/bin/sh", "/usr/bin/true", "/etc/hostname", "/etc/passwd"]

    case Enum.find(candidates, &Tightbeam.PairingFreeze.read(&1).lifted) do
      nil -> sudo_built_unfreeze_file!(candidates)
      path -> path
    end
  end

  defp sudo_built_unfreeze_file!(candidates) do
    case :persistent_term.get({__MODULE__, :unfreeze_file}, nil) do
      nil ->
        if System.get_env("CI") == "true" and
             match?({_, 0}, System.cmd("sudo", ["-n", "true"], stderr_to_stdout: true)) do
          base = Path.join(System.tmp_dir!(), "tb-unfreeze-#{System.unique_integer([:positive])}")
          File.mkdir_p!(base)
          etc = Path.join(base, "etc")
          dir = Path.join(etc, "tightbeam")
          file = Path.join(dir, "pairing-unfreeze")
          sudo!(["install", "-d", "-o", "root", "-g", "0", "-m", "0755", etc, dir])
          sudo!(["install", "-o", "root", "-g", "0", "-m", "0644", "/dev/null", file])

          unless Tightbeam.PairingFreeze.read(file).lifted,
            do:
              raise(
                "sudo-built unfreeze file is not valid: #{inspect(Tightbeam.PairingFreeze.read(file))}"
              )

          :persistent_term.put({__MODULE__, :unfreeze_file}, file)
          file
        else
          checks = Enum.map(candidates, &{&1, Tightbeam.PairingFreeze.read(&1)})

          raise "this host offers no root-owned fixture file for a valid unfreeze file " <>
                  "and no passwordless sudo on CI: #{inspect(checks)}"
        end

      file ->
        file
    end
  end

  defp sudo!(args) do
    case System.cmd("sudo", ["-n" | args], stderr_to_stdout: true) do
      {_, 0} -> :ok
      {output, status} -> raise "sudo #{inspect(args)} exited #{status}: #{output}"
    end
  end

  # Users go through the ordinary in-process writer so their projections exist;
  # the first user of an organization is admin by the shared cold-start rule.
  defp ensure_user(db, user_id, admin) do
    if is_nil(Devices.user(db, user_id)), do: Devices.add_user(db, user_id, admin)
    :ok
  end

  defp exec(db, sql, params) do
    case DB.query(db, sql, params) do
      {:ok, _rows} -> :ok
      {:error, error} -> raise error
    end
  end

  defp slug(claimed_name) do
    case claimed_name
         |> String.downcase()
         |> String.replace(~r/[^a-z0-9]+/, "-")
         |> String.trim("-") do
      "" -> "user"
      slug -> slug
    end
  end

  defp mint_token, do: "tbt_" <> Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)
  defp now, do: System.system_time(:millisecond)
end
