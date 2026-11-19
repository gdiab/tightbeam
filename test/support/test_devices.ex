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
          exec(db, "UPDATE devices SET token = ?2, tokenCollected = 1 WHERE deviceId = ?1", [
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
        token = if first?, do: mint_token()

        :ok =
          exec(
            db,
            """
            INSERT INTO devices
              (deviceId, userId, claimedName, status, token, platform, model, createdAt,
               tokenCollected)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1)
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
          mint_token(),
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

  @doc "The transport fields of a call made on `device`'s authenticated connection."
  @spec device_call(map(), map()) :: map()
  def device_call(device, call \\ %{}) do
    Map.merge(call, %{
      origin: "user:#{device.user_id}",
      principal: {:user, device.user_id},
      auth_class: "device",
      auth_device_id: device.device_id
    })
  end

  @doc """
  Stage 1 S2.1: issue a pairing code from `admin`'s paired device for `user` (the
  device's own by default). Returns `{code, record}`; the code is taken from the
  calling process's mailbox, as the requesting connection receives it.
  """
  @spec issue_code!(GenServer.server(), map(), String.t() | nil) :: {String.t(), map()}
  def issue_code!(db, admin, user \\ nil) do
    call = device_call(admin, %{verb: "approve-device", params: %{}})

    case Tightbeam.DeviceLifecycle.issue_code(db, call, user) do
      %{code_id: _} = record ->
        receive do
          {:tightbeam_ephemeral, text} ->
            [code] = Regex.run(~r/TB-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}/, text)
            {code, record}
        after
          0 -> raise "issue_code sent no ephemeral code"
        end

      refusal ->
        raise "issue_code refused: #{inspect(refusal)}"
    end
  end

  @doc "Stage 1 S2.2: a coded `pair_request` through `admission` (a PairingAdmission)."
  @spec coded_pair(GenServer.server(), String.t(), String.t(), String.t(), GenServer.server()) ::
          term()
  def coded_pair(db, device_id, name, code, admission) do
    Tightbeam.Devices.pair(
      db,
      %{device_id: device_id, claimed_name: "#{name} #{code}", platform: "ios", model: "iPhone"},
      admission: admission
    )
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
