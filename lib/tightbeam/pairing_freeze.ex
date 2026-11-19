defmodule Tightbeam.PairingFreeze do
  @moduledoc """
  The retired pairing freeze of core fix (A). Stage 1 lifts the freeze and retires its
  escape hatch (stage1-v8 S0.1): the gateway ignores the old unfreeze file, and at
  boot reports it once if it still exists (S0.2, `Tightbeam.DeviceLifecycle`). Nothing
  in Tightbeam creates, changes or removes the file.
  """

  @default_path "/etc/tightbeam/pairing-unfreeze"

  @doc """
  The old unfreeze file's path. Only a build compiled with the test-only override reads
  another path; every other build reads the fixed one.
  """
  @spec path() :: String.t()
  if Application.compile_env(:tightbeam, :pairing_unfreeze_path_override, false) do
    def path, do: Application.get_env(:tightbeam, :pairing_unfreeze_path, @default_path)
  else
    def path, do: @default_path
  end
end
