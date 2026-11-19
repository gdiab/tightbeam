defmodule Tightbeam.PairingFreeze do
  @moduledoc """
  The pairing freeze and the owner's escape hatch (core-v8 C6, C6a).

  While core fix (A) is installed no device token is issued or re-issued through
  pairing. The freeze is lifted exactly while the unfreeze file is valid:

  - the file is a regular file (not a symbolic link), owned by uid 0 and gid 0,
    and not writable by group or others;
  - its directory is owned by uid 0 and not writable by group or others;
  - that directory's parent is owned by uid 0 and not writable by group or others.

  Each is checked with `lstat`, so no symbolic link is followed. The contents are
  ignored. Nothing in Tightbeam creates, changes or removes the file: this module
  only reads it.

  The file is read at every pairing decision (each `pair_request` and each
  `approve-device`) in the handling step that acts on it, and once at boot, only
  to record and alert. The gateway's last observation is a durable row, so a
  frozen→lifted transition alerts once however many requests observe it.
  """

  require Logger
  import Bitwise

  alias Tightbeam.{DB, EventLog, Org, OwnerAlerts, Wakes}
  alias Tightbeam.DB.Txn

  @default_path "/etc/tightbeam/pairing-unfreeze"

  @frozen_message "Pairing is frozen on this gateway while the device-credential fix is " <>
                    "installed. Already-paired devices keep working. New devices, re-pairing " <>
                    "and total-loss recovery arrive with the device-lifecycle follow-on. Until " <>
                    "then, the gateway's owner can lift the freeze on the gateway host."

  @typedoc "One reading of the unfreeze file."
  @type state ::
          %{lifted: true, mtime: integer()}
          | %{lifted: false, invalid: nil | String.t(), mtime: integer() | nil}

  @doc "The refusal message for `pairing_frozen` (C6). It names no path."
  @spec frozen_message() :: String.t()
  def frozen_message, do: @frozen_message

  @doc "The `pairing_frozen` refusal map."
  @spec frozen_refusal() :: %{code: String.t(), message: String.t()}
  def frozen_refusal, do: %{code: "pairing_frozen", message: @frozen_message}

  @doc """
  The unfreeze file's path. Only a build compiled with the test-only override reads
  another path; every other build reads the fixed one.
  """
  @spec path() :: String.t()
  if Application.compile_env(:tightbeam, :pairing_unfreeze_path_override, false) do
    def path, do: Application.get_env(:tightbeam, :pairing_unfreeze_path, @default_path)
  else
    # A release reads only the fixed path: no setting can point the hatch elsewhere.
    def path, do: @default_path
  end

  @doc "Read the unfreeze file now, without following symbolic links."
  @spec read(String.t()) :: state()
  def read(file \\ path()) do
    dir = Path.dirname(file)
    parent = Path.dirname(dir)

    case File.lstat(file, time: :posix) do
      {:error, :enoent} ->
        %{lifted: false, invalid: nil, mtime: nil}

      {:error, reason} ->
        %{lifted: false, invalid: "file_unreadable:#{reason}", mtime: nil}

      {:ok, stat} ->
        invalid =
          check(stat, :regular, "file") || check_path(dir, "directory") ||
            check_path(parent, "parent_directory")

        if invalid,
          do: %{lifted: false, invalid: invalid, mtime: stat.mtime},
          else: %{lifted: true, mtime: stat.mtime}
    end
  end

  defp check_path(path, label) do
    case File.lstat(path, time: :posix) do
      {:ok, stat} -> check(stat, :directory, label)
      {:error, reason} -> "#{label}_unreadable:#{reason}"
    end
  end

  defp check(stat, type, label) do
    cond do
      stat.type != type -> "#{label}_not_#{type}:#{stat.type}"
      stat.uid != 0 -> "#{label}_owner_uid:#{stat.uid}"
      label == "file" and stat.gid != 0 -> "#{label}_owner_gid:#{stat.gid}"
      (stat.mode &&& 0o022) != 0 -> "#{label}_writable_by_group_or_others"
      true -> nil
    end
  end

  @doc """
  Record one pairing decision's observation inside its transaction: an invalid
  file, a frozen→lifted transition (alerting the owner twice), or a lifted→frozen
  restoration.
  """
  @spec observe_in_txn(Txn.t(), state(), keyword()) :: :ok
  def observe_in_txn(%Txn{} = txn, state, opts \\ []) do
    now = Keyword.get_lazy(opts, :now, &now/0)
    boot? = Keyword.get(opts, :boot, false)
    current = if state.lifted, do: "lifted", else: "frozen"

    previous =
      case Txn.q(txn, "SELECT state FROM pairing_freeze_observation WHERE id = 0") do
        [[value]] -> value
        [] -> "frozen"
      end

    if is_binary(Map.get(state, :invalid)) do
      EventLog.lifecycle_in_txn(
        txn,
        "pairing_unfreeze_invalid",
        path(),
        JSON.encode!(%{check: state.invalid, fileMtime: state.mtime, at: now})
      )
    end

    Txn.q(
      txn,
      """
      INSERT INTO pairing_freeze_observation (id, state, observedAt, fileMtime)
      VALUES (0, ?1, ?2, ?3)
      ON CONFLICT(id) DO UPDATE SET state = excluded.state, observedAt = excluded.observedAt,
        fileMtime = excluded.fileMtime
      """,
      [current, now, state.mtime]
    )

    cond do
      state.lifted and (boot? or previous != "lifted") ->
        alert_lifted_in_txn(txn, state.mtime, now)

      not state.lifted and previous == "lifted" ->
        EventLog.lifecycle_in_txn(
          txn,
          "pairing_freeze_restored",
          path(),
          JSON.encode!(%{at: now})
        )

      true ->
        :ok
    end

    :ok
  end

  @doc """
  Record a pairing decision taken while lifted (`pairing_freeze_lifted_use`).
  """
  @spec record_use_in_txn(Txn.t(), state(), String.t(), String.t() | nil, String.t()) :: :ok
  def record_use_in_txn(%Txn{} = txn, %{lifted: true, mtime: mtime}, verb, device_id, outcome) do
    EventLog.lifecycle_in_txn(
      txn,
      "pairing_freeze_lifted_use",
      device_id || "",
      JSON.encode!(%{
        at: now(),
        deviceId: device_id,
        verb: verb,
        outcome: outcome,
        fileMtime: mtime
      })
    )
  end

  def record_use_in_txn(%Txn{}, _state, _verb, _device_id, _outcome), do: :ok

  @doc "Boot: read the file once and record or alert; it decides nothing."
  @spec observe_at_boot(DB.server()) :: :ok
  def observe_at_boot(db \\ DB) do
    state = read()

    {:ok, :ok} = DB.transaction(db, &observe_in_txn(&1, state, boot: true))
    :ok
  rescue
    error ->
      Logger.error("pairing freeze boot observation failed: #{Exception.message(error)}")
      :ok
  end

  @doc "The alert text both alerts carry (C6a)."
  @spec lifted_alert_body(integer() | nil) :: String.t()
  def lifted_alert_body(mtime) do
    "The pairing freeze is lifted on the gateway host (file time #{format_mtime(mtime)}). " <>
      "Only new devices can pair, and only with your approval. Remove the file as soon as " <>
      "pairing is done. If you did not lift it, an agent did; remove it and check " <>
      "`/tightbeam pending-devices`."
  end

  defp alert_lifted_in_txn(txn, mtime, observed_at) do
    body = lifted_alert_body(mtime)

    # Through Harklight on the owner-alerts path, and to every admin's Main.
    _ = OwnerAlerts.pairing_freeze_lifted_in_txn(txn, observed_at, body)

    txn
    |> Txn.q("SELECT userId FROM users WHERE isAdmin = 1 AND removedAt IS NULL ORDER BY userId")
    |> Enum.each(fn [user_id] ->
      main = Org.personal_session_key(user_id)

      if Txn.q(txn, "SELECT 1 FROM sessions WHERE sessionKey = ?1", [main]) == [[1]] do
        Wakes.schedule_in_txn(txn, %{
          session_key: main,
          origin: "process:tightbeam",
          prompt: body,
          due_at: observed_at,
          class: "blocker",
          sender_scheduled: true
        })
      end
    end)

    EventLog.lifecycle_in_txn(
      txn,
      "pairing_freeze_lifted",
      path(),
      JSON.encode!(%{at: observed_at, fileMtime: mtime})
    )
  end

  defp format_mtime(nil), do: "unknown"

  defp format_mtime(mtime) when is_integer(mtime) do
    case DateTime.from_unix(mtime) do
      {:ok, at} -> DateTime.to_iso8601(at)
      _ -> Integer.to_string(mtime)
    end
  end

  defp now, do: System.system_time(:millisecond)
end
