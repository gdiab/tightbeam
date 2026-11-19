defmodule Tightbeam.Native do
  @moduledoc """
  The gateway's native helpers (native/tightbeam_native), stage 1 of the
  device-lifecycle follow-on:

  - `argon2id/2` computes the S0.3 verifier (Argon2id, m = 64 MiB, t = 3, p = 1,
    32-byte output) for a secret or code and a 16-byte salt, on a dirty CPU scheduler.
  - `base_lock/1` takes the S1.2 base-directory lock, an exclusive non-blocking
    `flock`, held for as long as the returned resource is referenced.
  """

  @on_load :load_nif

  @doc false
  def load_nif do
    :tightbeam
    |> Application.app_dir("priv/tightbeam_native")
    |> String.to_charlist()
    |> :erlang.load_nif(0)
  end

  @doc "The S0.3 Argon2id verifier of `secret` under the 16-byte `salt`."
  @spec argon2id(binary(), <<_::128>>) :: <<_::256>>
  def argon2id(_secret, _salt), do: :erlang.nif_error(:nif_not_loaded)

  @doc "Take the exclusive base-directory lock at `path`, or raise `:held`."
  @spec base_lock(String.t()) :: reference()
  def base_lock(_path), do: :erlang.nif_error(:nif_not_loaded)
end
