defmodule Tightbeam.HarklightAgent do
  @moduledoc """
  What the installed `harklight-agent` accepts for delivery receipts (ACK2).

  The gateway asks the listener and attach launches for ACK2 (`--ack2`) and
  reports each dispatched reply with the `ack2` command. An agent release
  without them rejects the argument at parse time (agent 0.1.3:
  `unexpected argument '--ack2' found`, `unrecognized subcommand 'ack2'`), so
  a listener asking for ACK2 would never start and replies would not be
  delivered. Each capability is read from the agent's own help, every time it
  is needed, so an upgraded agent is used as soon as it is installed:

    * `listen_ack2` and `attach_ack2`: the subcommand's help exits 0 and lists
      `--ack2`;
    * `ack2_command`: `ack2 --help` exits 0 and lists its `--event` option.

  Anything else, including a help call that fails or does not answer within
  #{5_000} ms, is unsupported: the launch leaves ACK2 out and the caller
  records that it did, so delivery continues without the receipt and the
  omission is never silent.
  """

  @help_timeout_ms 5_000

  @type capabilities :: %{
          listen_ack2: boolean(),
          attach_ack2: boolean(),
          ack2_command: boolean()
        }

  @doc """
  The capabilities of `executable`. Test builds may pin them through the
  `:harklight_agent_capabilities` application setting; `:detect` (the default)
  reads the agent's help.
  """
  @spec capabilities(String.t()) :: capabilities()
  def capabilities(executable) do
    case Application.get_env(:tightbeam, :harklight_agent_capabilities, :detect) do
      :detect -> detect(executable)
      %{listen_ack2: _, attach_ack2: _, ack2_command: _} = pinned -> pinned
    end
  end

  @doc false
  @spec detect(String.t()) :: capabilities()
  def detect(executable) do
    %{
      listen_ack2: lists?(help(executable, ["listen", "--help"]), "--ack2"),
      attach_ack2: lists?(help(executable, ["attach", "--help"]), "--ack2"),
      ack2_command: lists?(help(executable, ["ack2", "--help"]), "--event")
    }
  end

  @doc "The capability names that are unsupported, in a stable order."
  @spec omitted(capabilities(), [atom()]) :: [String.t()]
  def omitted(capabilities, names) do
    for name <- names, not Map.fetch!(capabilities, name), do: Atom.to_string(name)
  end

  defp lists?({output, 0}, option),
    do: Regex.match?(~r/(^|[\s,\[])#{Regex.escape(option)}([\s,=\]]|$)/m, output)

  defp lists?(_result, _option), do: false

  defp help(executable, args) do
    task =
      Task.async(fn ->
        try do
          System.cmd(executable, args, stderr_to_stdout: true, env: [{"NO_COLOR", "1"}])
        rescue
          _ -> :unanswered
        catch
          _, _ -> :unanswered
        end
      end)

    case Task.yield(task, @help_timeout_ms) || Task.shutdown(task, :brutal_kill) do
      {:ok, result} -> result
      _ -> :unanswered
    end
  end
end
