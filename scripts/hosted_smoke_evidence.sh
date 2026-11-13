#!/bin/sh
# Select the publishable lines of a feature_smoke.exs run. stdin: the run's raw
# combined output. stdout: only lines whose SHAPE is known, then one count line.
#
# The raw output is never published. It carries failure messages that quote gateway
# responses, and nothing guarantees those are free of bearers, provider bodies or
# private turn text. This is an allowlist of the lines the driver prints from fixed
# templates (scripts/feature_smoke.exs: announce_selection!/1, run/0, preflight!/2,
# pass/2, finish_leg/1), followed by a denylist of credential SHAPES applied even to
# allowed lines, because a PASS label interpolates a few stored values. A FAIL line
# is reduced to its marker: the message after it is withheld, not filtered.
#
# Masking secrets in a log is not redaction; selecting known shapes is. A line this
# script does not recognise is dropped and counted, never passed through.
set -eu
export LC_ALL=C

awk '
  function credential_shaped(line) {
    # A bearer header, the org token prefix, provider key prefixes, or any run of 32+
    # token alphabet characters (minted bearers and API keys are all longer than that).
    return line ~ /[Bb]earer|tbc_|sk-|sk_|[Aa][Pp][Ii][-_]?[Kk][Ee][Yy]|[A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-][A-Za-z0-9_+\/=-]/
  }

  function known(line) {
    if (length(line) > 400) return 0
    if (line ~ /^feature-smoke legs: [a-z, ]+ \(every registered leg — full parity\)$/) return 1
    if (line ~ /^feature-smoke legs: [a-z, ]+ — FILTERED, holding back [a-z, ]+\. /) return 1
    if (line ~ /^feature-smoke leg (claude|codex) model=[][A-Za-z0-9._:-]+$/) return 1
    if (line ~ /^credential preflight [A-Za-z0-9_.:-]+: (PASS|FAIL|INCOMPLETE)$/) return 1
    if (line ~ /^  PASS \[(claude|codex)\] [^\t]+$/) return 1
    if (line ~ /^feature-smoke leg (claude|codex): [0-9]+ checks PASS$/) return 1
    return 0
  }

  {
    if ($0 ~ /^  FAIL  /) { print "  FAIL  (message withheld: raw output stays on the runner)"; next }
    if (known($0) && !credential_shaped($0)) { print; next }
    withheld++
  }

  END { printf "evidence-filter: %d raw line(s) withheld\n", withheld + 0 }
'
