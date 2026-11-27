defmodule Tightbeam.TestRootPathTest do
  use ExUnit.Case, async: true

  Code.require_file("../config/test_root_path.exs", __DIR__)

  @tag :tmp_dir
  test "canonical root aliases accept only existing directories in the same physical tree", %{
    tmp_dir: tmp_dir
  } do
    root = Path.join(tmp_dir, "root")
    alias_path = Path.join(tmp_dir, "root-alias")
    inside = Path.join(root, "inside")
    outside = Path.join(tmp_dir, "outside")
    near_miss = Path.join(tmp_dir, "root-evil")

    File.mkdir_p!(inside)
    File.mkdir_p!(outside)
    File.mkdir_p!(near_miss)
    File.ln_s!(root, alias_path)
    File.ln_s!(outside, Path.join(root, "escape"))
    File.ln_s!(Path.join(root, "missing-target"), Path.join(root, "broken"))

    assert Tightbeam.TestRootPath.existing_directory_within?(inside, alias_path)
    refute Tightbeam.TestRootPath.existing_directory_within?(outside, alias_path)
    refute Tightbeam.TestRootPath.existing_directory_within?(near_miss, root)
    refute Tightbeam.TestRootPath.existing_directory_within?(Path.join(root, "missing"), root)
    refute Tightbeam.TestRootPath.existing_directory_within?(Path.join(root, "broken"), root)
    refute Tightbeam.TestRootPath.existing_directory_within?(Path.join(root, "escape"), root)
  end
end
