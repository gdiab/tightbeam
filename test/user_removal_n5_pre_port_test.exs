defmodule Tightbeam.UserRemovalN5PrePortTest do
  # Evidence for contract v2 (art_a823f882) N5 / R0 on the PRE-PORT 0.1.16 tip
  # 1ca470a6: this build has no user-removal step and no adoption, so F0 (a
  # user-removal-v1-0114 base marked by 0.1.14 + PR622) is refused before any
  # migration and left exactly as it was. Not a product change; never proposed.
  use Tightbeam.TestCase, async: false

  alias Tightbeam.{LiveBaseAdmission, LiveBaseGuard, Schema}

  @f0_dir Path.expand("fixtures/user_removal/f0", __DIR__)

  test "N5: the pre-port 0.1.16 build refuses F0 before ensure_all and changes nothing" do
    suffix = System.unique_integer([:positive])
    root = Path.join(File.cwd!(), ".tmp-n5-#{suffix}")
    base = Path.join(File.cwd!(), ".tmp-n5-base-#{suffix}")
    app = Path.join(root, "release/lib/tightbeam-0.1.16")
    File.mkdir_p!(Path.join(app, "ebin"))
    File.mkdir_p!(Path.join(app, "priv"))
    File.write!(Path.join(app, "ebin/fixture.beam"), "fixture beam")
    File.write!(Path.join(app, "priv/fixture.rule"), "fixture rule")
    File.mkdir_p!(Path.join(root, "bin"))
    File.write!(Path.join(root, "package.json"), ~s({"name":"tightbeam"}))
    File.write!(Path.join(root, "bin/tightbeam"), "fixture")
    File.write!(Path.join(root, "bin/tightbeam-gateway"), "fixture")
    File.write!(Path.join(root, "release/README"), "fixture")

    File.write!(
      Path.join(root, "release-provenance.json"),
      JSON.encode!(%{
        "commit" => String.duplicate("a", 40),
        "format" => "tightbeam-release-provenance/v1",
        "repository" => "clickety-clacks/tightbeam",
        "tag" => "v0.1.16+1"
      })
    )

    {:ok, manifest} = LiveBaseGuard.generate_manifest(LiveBaseAdmission.payload_files!(app))
    File.write!(Path.join(app, "build-manifest.json"), JSON.encode!(manifest))

    on_exit(fn ->
      File.rm_rf!(root)
      File.rm_rf!(base)
    end)

    bytes =
      @f0_dir
      |> Path.join("state.db.gz.b64")
      |> File.read!()
      |> String.replace(~r/\s/, "")
      |> Base.decode64!()
      |> :zlib.gunzip()

    recorded = @f0_dir |> Path.join("state.db.sha256") |> File.read!() |> String.trim()
    assert :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower) == recorded

    File.mkdir_p!(base)
    File.write!(Path.join(base, "state.db"), bytes)
    File.cp!(Path.join(@f0_dir, "build-owner.json"), Path.join(base, "build-owner.json"))
    marker = File.read!(Path.join(base, "build-owner.json"))
    %{"buildIdentity" => source} = JSON.decode!(marker)

    refute "user-removal-v1-0114" in Schema.guard_compatible_stamps()

    # The automatic release transition admits only listed stamps.
    assert_raise LiveBaseAdmission.Refusal, ~r/build_transition_required/, fn ->
      LiveBaseAdmission.prepare!(base, payload_root: app)
    end

    # An explicit operator transition reaches the guard, which refuses the stamp.
    transition =
      JSON.encode!(%{
        "base" => LiveBaseAdmission.canonical!(base),
        "source" => source,
        "target" => manifest["buildIdentity"]
      })

    error =
      assert_raise Schema.ShapeError, fn ->
        LiveBaseAdmission.prepare!(base, payload_root: app, transition: transition)
      end

    assert error.message =~ "incompatible_schema"
    IO.puts("N5-REFUSAL #{error.message}")

    assert File.read!(Path.join(base, "state.db")) == bytes
    assert File.read!(Path.join(base, "build-owner.json")) == marker
  end
end
