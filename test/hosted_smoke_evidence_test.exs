defmodule Tightbeam.HostedSmokeEvidenceTest do
  # scripts/hosted_smoke_evidence.sh is the ONLY path by which a live feature-smoke run's
  # output leaves the disposable runner. Its contract is a selection, not a mask: known
  # lines pass, everything else is dropped and counted, and a credential-shaped value is
  # dropped even inside a line whose template is known.
  use ExUnit.Case, async: true

  @script Path.expand("../scripts/hosted_smoke_evidence.sh", __DIR__)

  defp filter(lines) do
    dir = Path.join(System.tmp_dir!(), "hosted-smoke-evidence-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    input = Path.join(dir, "smoke.out")
    File.write!(input, Enum.join(lines, "\n") <> "\n")

    try do
      {out, 0} = System.cmd("sh", ["-c", ~s(sh "$0" < "$1"), @script, input])
      String.split(out, "\n", trim: true)
    after
      File.rm_rf!(dir)
    end
  end

  test "the driver's fixed-template lines are published verbatim" do
    lines = [
      "feature-smoke legs: claude, codex (every registered leg — full parity)",
      "feature-smoke leg claude model=claude-sonnet-5",
      "credential preflight P2: PASS",
      "  PASS [claude] onboard registered providers interactive entry",
      "  PASS [codex] toplines board reflects this run: 3 items, resolved membership, live progress clock, recorded creation context",
      "feature-smoke leg codex: 14 checks PASS"
    ]

    assert filter(lines) == lines ++ ["evidence-filter: 0 raw line(s) withheld"]
  end

  test "a FAIL line keeps its marker and loses its message" do
    out = filter(["  FAIL  spawn errored: %{\"raw\" => \"provider said: invalid x-api-key\"}"])

    assert out == [
             "  FAIL  (message withheld: raw output stays on the runner)",
             "evidence-filter: 0 raw line(s) withheld"
           ]
  end

  test "unknown lines never pass, and are counted" do
    out =
      filter([
        "12:00:01.000 [info] ACP adapter install into /tmp/org/adapters on runner complete",
        "** (RuntimeError) credential preflight failed: provider returned 401 {\"error\":\"...\"}",
        "Authorization: Bearer tbc_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      ])

    assert out == ["evidence-filter: 3 raw line(s) withheld"]
  end

  test "a known template carrying a credential-shaped value is dropped, not published" do
    out =
      filter([
        "  PASS [claude] carrier on a real claude turn: tbc_q9Zx tool-call-observed",
        "  PASS [codex] gate chain released by a sk-proj-abcdefghijklmnopqrstuvwxyz0123456789 row",
        "  PASS [claude] label with an opaque abcdefghijklmnopqrstuvwxyz0123456789ABCD value",
        "  PASS [codex] label with Bearer in it"
      ])

    assert out == ["evidence-filter: 4 raw line(s) withheld"]
  end

  test "a wrong harness name or an altered completion line is not a known shape" do
    out =
      filter([
        "  PASS [fixture] some check",
        "feature-smoke leg codex: 14 checks PASS (extra)",
        "feature-smoke leg claude model=claude sonnet"
      ])

    assert out == ["evidence-filter: 3 raw line(s) withheld"]
  end
end
