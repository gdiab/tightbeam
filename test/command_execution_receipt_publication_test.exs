defmodule Tightbeam.CommandExecutionReceiptPublicationTest do
  use ExUnit.Case, async: true
  @moduletag tmp_dir: true

  alias Tightbeam.CommandExecutions

  test "JSON receipt is not visible until complete and flushed", %{tmp_dir: tmp} do
    final_path = Path.join(tmp, "terminal.json")
    value = %{"executionId" => "held-writer", "exitCode" => 0}
    parent = self()

    writer =
      Task.async(fn ->
        CommandExecutions.write_json_once_for_test(final_path, value, fn held_path ->
          send(parent, {:writer_held, self(), held_path})

          receive do
            :release_writer -> :ok
          end
        end)
      end)

    assert_receive {:writer_held, writer_pid, held_path}
    final_while_held = File.read(final_path)
    staged_while_held = File.read(held_path)
    send(writer_pid, :release_writer)
    assert :ok = Task.await(writer)

    refute held_path == final_path
    assert {:error, :enoent} = final_while_held
    assert {:ok, staged_bytes} = staged_while_held
    assert JSON.decode!(staged_bytes) == value
    assert final_path |> File.read!() |> JSON.decode!() == value
  end

  test "JSON receipt publication refuses to clobber", %{tmp_dir: tmp} do
    final_path = Path.join(tmp, "terminal.json")
    original = "{\"executionId\":\"first\"}\n"
    File.write!(final_path, original)

    assert {:error, :eexist} =
             CommandExecutions.write_json_once_for_test(
               final_path,
               %{"executionId" => "second"},
               fn _path -> :ok end
             )

    assert File.read!(final_path) == original
    assert Path.wildcard(Path.join(tmp, ".terminal.json.tmp-*")) == []
  end

  test "crash-leftover temp file is not receipt evidence", %{tmp_dir: tmp} do
    final_path = Path.join(tmp, "terminal.json")
    leftover_path = Path.join(tmp, ".terminal.json.tmp-crash")
    leftover = "{\"executionId\":"
    File.write!(leftover_path, leftover)

    assert {:error, :enoent} = File.read(final_path)

    assert :ok =
             CommandExecutions.write_json_once_for_test(
               final_path,
               %{"executionId" => "published"},
               fn _path -> :ok end
             )

    assert final_path |> File.read!() |> JSON.decode!() == %{"executionId" => "published"}
    assert File.read!(leftover_path) == leftover
  end
end
