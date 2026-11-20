defmodule Tightbeam.ApplicationServicePathTest do
  # Core fix (A), C21.1: the packaged launcher runs the release's launch scripts on a
  # system-only PATH and hands the service's PATH over in TIGHTBEAM_GATEWAY_PATH
  # (isolated_lifecycle_isolation_test). The gateway restores it at start, so harness
  # CLIs resolve as before. Not async: it changes this VM's PATH.
  use Tightbeam.TestCase, async: false

  alias Tightbeam.Application, as: App

  setup do
    path = System.get_env("PATH")
    on_exit(fn -> System.put_env("PATH", path) end)
    %{path: path}
  end

  test "the handed-over service PATH is restored and the hand-over variable removed", %{
    path: path
  } do
    System.put_env("PATH", "/usr/bin:/bin")
    System.put_env("TIGHTBEAM_GATEWAY_PATH", path)

    App.restore_service_path()

    assert System.get_env("PATH") == path
    assert System.get_env("TIGHTBEAM_GATEWAY_PATH") == nil
  end

  test "without a hand-over, PATH is left alone", %{path: path} do
    System.delete_env("TIGHTBEAM_GATEWAY_PATH")
    App.restore_service_path()
    assert System.get_env("PATH") == path
  end
end
