defmodule Tightbeam.OpencodeLaunchInvariantsTest.ReuseProbeShimHarness do
  @moduledoc false
  # A SECOND, synthetic binary-native harness — distinct from OpenCode — that reuses the generic
  # shim seam by supplying its OWN cli_binary + subcommand, with NO edit to the shared helper
  # (harness.ex/spinup.ex/support.ex). This is the Cursor reuse contract in miniature: if anything
  # opencode-specific had leaked into `Spinup.ensure_shim_adapter/4`, this harness could not use it.
  # A plain module (not `@behaviour`) on purpose — it exercises only the shim surface, not the whole
  # behaviour, so it stays lightweight and warning-free.
  def adapter_provisioning, do: :shim
  def cli_binary, do: "probe-agent"
  def install_package, do: "probe-agent"

  def ensure_adapter(target) do
    shim =
      Path.join([target.host_config.base_dir, "adapters", "node_modules", ".bin", "probe-agent"])

    Tightbeam.Spinup.ensure_shim_adapter(target, shim, cli_binary(), ["bridge"])
  end
end

defmodule Tightbeam.OpencodeLaunchInvariantsTest do
  # The rails-critical launch invariants for the OpenCode harness, tested structurally where the
  # conformance suite cannot: the shim can carry no plugin-disabling/listener-opening flag, the
  # launch argv is exactly the shim, the gate env is wired and OPENCODE_PURE never is, and the
  # 0-LISTEN assertion is automatic for the :shim class (safe-by-default).
  use Tightbeam.TestCase, async: false

  import Bitwise, only: [band: 2]

  alias Tightbeam.{Harness, Spinup}
  alias Tightbeam.Harness.Opencode

  @forbidden ["--pure", "serve", "--port", "--hostname", "--mdns", "--cors"]

  describe "shim mechanism (invariants 1 & 2, structural)" do
    test "the shim bakes the fixed subcommand and carries no plugin-disabling/listener-opening flag" do
      base = Path.join(System.tmp_dir!(), "oc-shim-#{System.unique_integer([:positive])}")
      cli = Path.join(base, "opencode-bin")
      shim = Path.join([base, "adapters", "node_modules", ".bin", "opencode"])
      File.mkdir_p!(base)
      File.write!(cli, "#!/bin/sh\n")
      File.chmod!(cli, 0o755)

      target = %{
        host_name: "t",
        host_config: %{ssh: nil, base_dir: base},
        find_executable: fn "opencode" -> cli end
      }

      assert {:ok, "shim adapter present"} =
               Spinup.ensure_shim_adapter(target, shim, "opencode", ["acp"])

      content = File.read!(shim)
      assert content == "#!/bin/sh\nexec \"#{cli}\" acp \"$@\"\n"
      for flag <- @forbidden, do: refute(content =~ flag, "shim must never carry #{flag}")
      assert band(File.stat!(shim).mode, 0o777) == 0o755

      File.rm_rf!(base)
    end

    test "a missing operator CLI is a loud refusal, never a silent stub" do
      base = Path.join(System.tmp_dir!(), "oc-shim-miss-#{System.unique_integer([:positive])}")
      File.mkdir_p!(base)
      shim = Path.join(base, "opencode")

      target = %{
        host_name: "t",
        host_config: %{ssh: nil, base_dir: base},
        find_executable: fn "opencode" -> nil end
      }

      assert {:error, %{code: "host_unready", message: message}} =
               Spinup.ensure_shim_adapter(target, shim, "opencode", ["acp"])

      assert message =~ "opencode"
      refute File.exists?(shim)
      File.rm_rf!(base)
    end
  end

  describe "prepare_launch (invariants 1 & 2 at the launch seam)" do
    test "cmd is exactly the shim with no extra argv; the gate is wired and OPENCODE_PURE never is" do
      base = "/base"
      home = "/base/homes/h/opencode"
      adapter = "/base/adapters/node_modules/.bin/opencode"

      target = %{
        host_config: %{ssh: nil, base_dir: base},
        adapter_binary: adapter
      }

      plan =
        Opencode.prepare_launch(target, home,
          common_env: [{"COMMON", "1"}],
          remote_env: [],
          lineage: "l"
        )

      # The whole argv is the shim — nothing appends a flag, so `--pure`/`serve`/`--port` cannot
      # reach the CLI (the shim itself bakes in `acp`).
      assert plan[:cmd] == [adapter]
      for token <- plan[:cmd], flag <- @forbidden, do: refute(token =~ flag)

      env = Map.new(plan[:env])
      assert env["OPENCODE_CONFIG"] == "/base/opencode-gate/opencode.json"
      assert env["OPENCODE_DISABLE_PROJECT_CONFIG"] == "1"
      assert env["XDG_DATA_HOME"] == "/base/homes/h"
      assert env["XDG_CONFIG_HOME"] == "/base/homes/h"
      refute Map.has_key?(env, "OPENCODE_PURE")
    end
  end

  describe "0-LISTEN assertion (invariant 3, automatic for the :shim class)" do
    test "requires_zero_listeners?/1 is safe-by-default: enforced for :shim, not for :npm" do
      # OpenCode gets it automatically by being :shim — it declares no per-harness property.
      assert Harness.requires_zero_listeners?(Tightbeam.Harness.Opencode)
      refute function_exported?(Tightbeam.Harness.Opencode, :requires_zero_listeners?, 0)

      # The :npm path is not enforced in this goal.
      refute Harness.requires_zero_listeners?(Tightbeam.Harness.Claude)
      refute Harness.requires_zero_listeners?(Tightbeam.Harness.Codex)
      refute Harness.requires_zero_listeners?(Tightbeam.Harness.Fixture)
    end
  end

  describe "provisioning strategy (shared shim seam)" do
    test "opencode is :shim and is excluded from the npm-provisioned set; the others are :npm" do
      assert Opencode.adapter_provisioning() == :shim
      refute Opencode in Harness.npm_provisioned()
      assert Tightbeam.Harness.Claude in Harness.npm_provisioned()
      assert Tightbeam.Harness.Codex in Harness.npm_provisioned()
    end

    test "registration is live and provisioning refuses every version except the temporary pin" do
      assert Opencode in Harness.all()
      assert Harness.module!(:opencode) == Opencode
      assert Harness.parse!("opencode") == Opencode
      assert Opencode.adapter_version() == "1.0.41"

      base = Path.join(System.tmp_dir!(), "oc-pin-#{System.unique_integer([:positive])}")
      cli = Path.join(base, "opencode-bin")
      File.mkdir_p!(base)
      File.write!(cli, "#!/bin/sh\n")
      File.chmod!(cli, 0o755)

      target = %{
        host_name: "t",
        host_config: %{ssh: nil, base_dir: base},
        find_executable: fn "opencode" -> cli end,
        run: fn [^cli, "--version"] -> {"1.0.41\n", 0} end
      }

      assert {:ok, "shim adapter present"} = Opencode.ensure_adapter(target)

      wrong = %{target | run: fn [^cli, "--version"] -> {"1.18.18\n", 0} end}

      assert {:error, %{code: "host_unready", message: message}} =
               Opencode.ensure_adapter(wrong)

      assert message =~ "1.18.18"
      assert message =~ "requires the temporary rails pin 1.0.41"

      File.rm_rf!(base)
    end
  end

  describe "remote pin probe reads through ssh chatter (blocker att_13a3220d)" do
    # The remote branch of ensure_pinned_cli/1 runs `opencode --version` through `target.sh`,
    # which in production is Spinup.ensure_ready's default Support.system_cmd/1 — stderr merged
    # into stdout. ssh chatters on stderr even on SUCCESS, so a correctly-pinned host arrives as
    # "Warning: ...\n1.0.41". Reading the whole output refused exactly the hosts the pin exists
    # to admit and named the ssh warning as the installed version. Every leg below carries that
    # chatter, because a probe that only works on a silent first-hop is the bug.
    @chatter "Warning: Permanently added 'remote' (ED25519) to the list of known hosts.\n"

    # A remote target (ssh != nil) whose sh mock carries ssh chatter on every ssh-carried leg:
    # the --version pin probe, the `command -v` shim resolve, and the shim/gate write scripts.
    defp remote_target(base, reported_version) do
      %{
        host_name: "remote-host",
        host_config: %{ssh: "vector@remote", base_dir: base},
        sh: fn command ->
          joined = Enum.join(command, " ")

          cond do
            String.contains?(joined, "--version") ->
              {@chatter <> reported_version <> "\n", 0}

            String.contains?(joined, "command -v") ->
              {@chatter <> Path.join(base, "opencode") <> "\n", 0}

            # shim write + gate materialization scripts: succeed.
            true ->
              {"", 0}
          end
        end
      }
    end

    test "chatter + true 1.0.41 is ACCEPTED (the warning must not cost a pinned host placement)" do
      base = Path.join(System.tmp_dir!(), "oc-remote-ok-#{System.unique_integer([:positive])}")
      File.mkdir_p!(base)

      assert {:ok, "shim adapter present"} =
               Opencode.ensure_adapter(remote_target(base, "1.0.41"))

      File.rm_rf!(base)
    end

    test "chatter + true wrong version is REFUSED and reports the REAL version, not the chatter" do
      base = Path.join(System.tmp_dir!(), "oc-remote-wrong-#{System.unique_integer([:positive])}")
      File.mkdir_p!(base)

      assert {:error, %{code: "host_unready", message: message}} =
               Opencode.ensure_adapter(remote_target(base, "1.18.18"))

      assert message =~ "1.18.18"
      assert message =~ "requires the temporary rails pin 1.0.41"
      refute message =~ "Warning"
      refute message =~ "known hosts"

      File.rm_rf!(base)
    end

    test "the pin stays EXACT under trailing-line reading: near versions behind chatter are refused" do
      base = Path.join(System.tmp_dir!(), "oc-remote-near-#{System.unique_integer([:positive])}")
      File.mkdir_p!(base)

      # Last-line reading is not prefix/substring matching: a version that contains or trails the
      # pin is still refused, and the refusal names that real version.
      for near <- ["1.0.410", "v1.0.41", "1.0.41-beta"] do
        assert {:error, %{code: "host_unready", message: message}} =
                 Opencode.ensure_adapter(remote_target(base, near))

        assert message =~ near
      end

      File.rm_rf!(base)
    end

    test "scope: the LOCAL branch is untouched — it still reads the whole output, not the last line" do
      # The local branch execs the binary directly (Support.bounded_probe), where there is no ssh
      # to chatter, so it still trims the WHOLE output. This proves the fix is remote-only: a
      # multi-line local answer is NOT last-lined into acceptance.
      base = Path.join(System.tmp_dir!(), "oc-local-scope-#{System.unique_integer([:positive])}")
      cli = Path.join(base, "opencode-bin")
      File.mkdir_p!(base)
      File.write!(cli, "#!/bin/sh\n")
      File.chmod!(cli, 0o755)

      local = fn output ->
        %{
          host_name: "t",
          host_config: %{ssh: nil, base_dir: base},
          find_executable: fn "opencode" -> cli end,
          run: fn [^cli, "--version"] -> {output, 0} end
        }
      end

      assert {:ok, "shim adapter present"} = Opencode.ensure_adapter(local.("1.0.41\n"))

      assert {:error, %{code: "host_unready"}} =
               Opencode.ensure_adapter(local.("something odd\n1.0.41\n"))

      File.rm_rf!(base)
    end
  end

  describe "fetch_catalog (no fabricated catalog in production)" do
    test "with no wired source it FAILS LOUD rather than inventing a catalog" do
      assert {:error, :opencode_catalog_source_unwired} = Opencode.fetch_catalog(%{})
      assert {:error, :opencode_catalog_source_unwired} = Opencode.fetch_catalog(%{options: %{}})
    end

    test "the injected fetcher (conformance only) derives a provider-stamped entry" do
      state = %{options: %{opencode_fetch: fn -> {:ok, :valid} end}}

      assert {:ok, [%{provider: :opencode, family: "opencode/zen"}]} =
               Opencode.fetch_catalog(state)

      assert {:error, :malformed_catalog} =
               Opencode.fetch_catalog(%{options: %{opencode_fetch: fn -> {:ok, :other} end}})
    end
  end

  describe "reuse contract (the shared shim seam is generic, nothing opencode-specific leaked)" do
    alias Tightbeam.OpencodeLaunchInvariantsTest.ReuseProbeShimHarness, as: ReuseShim

    test "a second synthetic shim harness reuses Spinup.ensure_shim_adapter with its own binary + subcommand" do
      base = Path.join(System.tmp_dir!(), "reuse-shim-#{System.unique_integer([:positive])}")
      cli = Path.join(base, "probe-agent-bin")
      File.mkdir_p!(base)
      File.write!(cli, "#!/bin/sh\n")
      File.chmod!(cli, 0o755)

      target = %{
        host_name: "t",
        host_config: %{ssh: nil, base_dir: base},
        find_executable: fn "probe-agent" -> cli end
      }

      assert {:ok, "shim adapter present"} = ReuseShim.ensure_adapter(target)

      shim = Path.join([base, "adapters", "node_modules", ".bin", "probe-agent"])
      content = File.read!(shim)

      # Keyed ENTIRELY on this harness's own values — a different binary and a different
      # subcommand than opencode's — proving cli_binary + exec_args are fully parameterized and
      # no opencode literal ("acp"/"opencode") is baked into the shared helper.
      assert content == "#!/bin/sh\nexec \"#{cli}\" bridge \"$@\"\n"
      refute content =~ "opencode"
      refute content =~ "acp"

      # adapter_provisioning drives the generic exclusion AND the safe-by-default 0-LISTEN assert:
      # a second :shim harness gets invariant-3 protection AUTOMATICALLY, without opting in and with
      # nothing hardcoded to opencode — exactly the safe-by-default the ruling requires.
      assert ReuseShim.adapter_provisioning() == :shim
      assert Harness.requires_zero_listeners?(ReuseShim)

      File.rm_rf!(base)
    end
  end
end
