#!/usr/bin/env bash
# Live feature smoke, BOTH real harnesses, on a fresh org that exists only on this
# disposable machine. Driven by .github/workflows/live-feature-smoke.yml on a fresh
# GitHub-hosted VM; run from the root of the exact candidate checkout after it is built.
#
# The isolation boundary is the VM, not anything in this script. The org, its database,
# its minted bearers and the provider keys it banks live under RUN_ROOT on that VM's
# disk. GitHub provisions a new VM for the job and decommissions it when the job
# finishes; that is a backstop only, and this script must still prove its own teardown
# (stop, then removal of RUN_ROOT) for the run to pass. It never copies anything from
# another org or host, never reads a home it did not create, and publishes only what
# scripts/hosted_smoke_evidence.sh selects.
#
# Required environment (the workflow supplies every one):
#   SMOKE_RUN_ROOT            a path that must not exist yet; everything private goes here
#   SMOKE_EVIDENCE_DIR        a path that must not exist yet; the ONLY publishable output
#   SMOKE_PROVIDER_ANTHROPIC  dedicated test API key; moved out of the environment at once,
#   SMOKE_PROVIDER_OPENAI     piped once to `onboard --api-key` on stdin, then discarded
#   TIGHTBEAM_SMOKE_MODEL_CLAUDE / _EFFORT_CLAUDE / _MODEL_CODEX / _EFFORT_CODEX
#   SMOKE_WORKFLOW_SHA        the workflow definition revision, recorded beside the candidate
#
# Exit status 0 (verdict PASS) needs ALL of: this script itself reached its end with
# status 0 and was not interrupted, feature_smoke.exs exited 0, both registered legs
# reported their completion line at full parity, the gateway and every process it owned
# are confirmed gone by its supervisor, and RUN_ROOT (banked keys, minted bearers) is
# removed. Every other path exits non-zero and records the phase reached and why teardown,
# if it did, fell short. Failure detail stays in RUN_ROOT/private on the runner; nothing
# is retried, and a failed stop is never attempted again.
set -euo pipefail
umask 077

: "${SMOKE_RUN_ROOT:?}" "${SMOKE_EVIDENCE_DIR:?}" "${SMOKE_WORKFLOW_SHA:?}"
: "${SMOKE_PROVIDER_ANTHROPIC:?}" "${SMOKE_PROVIDER_OPENAI:?}"
: "${TIGHTBEAM_SMOKE_MODEL_CLAUDE:?}" "${TIGHTBEAM_SMOKE_EFFORT_CLAUDE:?}"
: "${TIGHTBEAM_SMOKE_MODEL_CODEX:?}" "${TIGHTBEAM_SMOKE_EFFORT_CODEX:?}"

REPO=$(pwd -P)
# shellcheck source=scripts/hosted_smoke_lifecycle.sh
. "$REPO/scripts/hosted_smoke_lifecycle.sh"
[ -x "$REPO/cli/target/release/tightbeam" ] || { echo "hosted-smoke: build the CLI first (cli/target/release/tightbeam)" >&2; exit 2; }
for p in "$SMOKE_RUN_ROOT" "$SMOKE_EVIDENCE_DIR"; do
  [ ! -e "$p" ] && [ ! -L "$p" ] || { echo "hosted-smoke: refusing to reuse existing $p" >&2; exit 2; }
done

mkdir -p "$SMOKE_RUN_ROOT/private" "$SMOKE_EVIDENCE_DIR"
BASE="$SMOKE_RUN_ROOT/org"
PRIVATE="$SMOKE_RUN_ROOT/private"
GATEWAY_LOG="$PRIVATE/gateway.log"
OWNER=smoke-owner
# Fixed loopback port on a fresh VM; the boot below refuses if anything already answers it.
PORT=4790
CLI="$REPO/cli/target/release/tightbeam"
PHASE=start
SMOKE_RC=
BOOT=0
SUPERVISOR="$REPO/scripts/hosted_smoke_supervisor.py"

# The provider keys leave the ENVIRONMENT before anything is launched: they move into
# unexported shell variables, which no child inherits, and the only place either is
# written is the stdin of its onboarding command (via the printf builtin, so no argv).
anthropic_key=$SMOKE_PROVIDER_ANTHROPIC
openai_key=$SMOKE_PROVIDER_OPENAI
unset SMOKE_PROVIDER_ANTHROPIC SMOKE_PROVIDER_OPENAI

export TIGHTBEAM_BASE_DIR="$BASE"

note() { printf 'hosted-smoke: %s\n' "$*"; }

record_identity() {
  # Nonsecret identity of everything this run depends on. The candidate and workflow
  # revisions are recorded separately on purpose: one is under test, one ran the test.
  {
    printf '{\n'
    printf '  "candidate_commit": "%s",\n' "$(git rev-parse HEAD)"
    printf '  "candidate_tree": "%s",\n' "$(git rev-parse 'HEAD^{tree}')"
    printf '  "workflow_sha": "%s",\n' "$SMOKE_WORKFLOW_SHA"
    printf '  "mix_lock_sha256": "%s",\n' "$(sha256sum mix.lock | cut -d' ' -f1)"
    printf '  "cargo_lock_sha256": "%s",\n' "$(sha256sum cli/Cargo.lock | cut -d' ' -f1)"
    printf '  "feature_smoke_sha256": "%s",\n' "$(sha256sum scripts/feature_smoke.exs | cut -d' ' -f1)"
    printf '  "cli_sha256": "%s",\n' "$(sha256sum "$CLI" | cut -d' ' -f1)"
    printf '  "elixir": "%s",\n' "$(elixir --version 2>/dev/null | tail -n1 | tr -d '"')"
    printf '  "otp": "%s",\n' "$(erl -noshell -eval 'io:put_chars(erlang:system_info(otp_release)), halt().' 2>/dev/null)"
    printf '  "rustc": "%s",\n' "$(rustc --version | tr -d '"')"
    printf '  "node": "%s",\n' "$(node --version)"
    printf '  "npm": "%s",\n' "$(npm --version)"
    printf '  "claude_cli": "%s",\n' "$(claude --version 2>/dev/null | head -n1 | tr -d '"')"
    printf '  "codex_cli": "%s",\n' "$(codex --version 2>/dev/null | head -n1 | tr -d '"')"
    printf '  "sqlite3": "%s",\n' "$(sqlite3 --version | cut -d' ' -f1)"
    printf '  "python3": "%s",\n' "$(python3 --version | cut -d' ' -f2)"
    printf '  "kernel": "%s",\n' "$(uname -r)"
    printf '  "supervisor_sha256": "%s",\n' "$(sha256sum "$SUPERVISOR" | cut -d' ' -f1)"
    printf '  "adapter_claude": "%s",\n' "$(sed -n 's/^  @adapter_version "\(.*\)"$/\1/p' lib/tightbeam/harness/claude.ex)"
    printf '  "adapter_codex": "%s",\n' "$(sed -n 's/^  @adapter_version "\(.*\)"$/\1/p' lib/tightbeam/harness/codex.ex)"
    printf '  "runner_os": "%s",\n' "$(. /etc/os-release && printf '%s' "$PRETTY_NAME")"
    printf '  "runner_arch": "%s",\n' "$(uname -m)"
    printf '  "legs": {"claude": {"model": "%s", "effort": "%s"}, "codex": {"model": "%s", "effort": "%s"}}\n' \
      "$TIGHTBEAM_SMOKE_MODEL_CLAUDE" "$TIGHTBEAM_SMOKE_EFFORT_CLAUDE" \
      "$TIGHTBEAM_SMOKE_MODEL_CODEX" "$TIGHTBEAM_SMOKE_EFFORT_CODEX"
    printf '}\n'
  } > "$SMOKE_EVIDENCE_DIR/identity.json"
}

version_answers() {
  curl -fsS --max-time 2 "http://127.0.0.1:$PORT/version" 2>/dev/null | grep -q '"protocolVersion":1'
}

# Same bounds as Tightbeam.ClientE2E.LegGateway (boot readiness 60 s; the supervisor's
# stop waits 30 s for the gateway and 15 s for the rest of its tree), without its
# MIX_ENV=test registry: the gateway under test runs the default environment, whose
# registry is exactly the real harnesses this smoke must cover. Each boot is owned by
# its own supervisor (scripts/hosted_smoke_lifecycle.sh, hosted_smoke_supervisor.py).
boot_gateway() {
  if version_answers; then
    echo "hosted-smoke: something already answers port $PORT; refusing to boot over it" >&2
    return 1
  fi
  BOOT=$((BOOT + 1))
  start_gateway_supervised "$PRIVATE/supervisor-$BOOT" "$GATEWAY_LOG" \
    env TIGHTBEAM_BASE_DIR="$BASE" TIGHTBEAM_PORT="$PORT" TIGHTBEAM_EFFORT_CHECKIN_HORIZON_MS=2500 \
    mix run --no-halt --no-start -e \
    'Application.put_env(:tightbeam, :autostart, true); Application.put_env(:tightbeam, :base_dir, System.fetch_env!("TIGHTBEAM_BASE_DIR")); Application.put_env(:tightbeam, :port, String.to_integer(System.fetch_env!("TIGHTBEAM_PORT"))); Application.ensure_all_started(:tightbeam)'
  local deadline=$((SECONDS + 60))
  until version_answers; do
    gateway_supervised || { echo "hosted-smoke: gateway exited during boot" >&2; return 1; }
    [ "$SECONDS" -lt "$deadline" ] || { echo "hosted-smoke: /version did not answer within 60 s" >&2; return 1; }
    sleep 0.5
  done
}

log_count() { grep -c -- "$1" "$GATEWAY_LOG" 2>/dev/null || true; }

# Wait for THIS boot's readiness verdict, which the gateway prints once, after its
# adapter install and catalog refresh settle. While an ACP adapter install is open
# (Tightbeam.Spinup's start line without its closing line) the silence is npm, not a
# hang, so the 60 s bound runs only from the last moment no install was open. A
# cold-cache install that never ends is stopped by the job's own timeout, not here.
await_verdict() {
  local before=$1 waited_from=$SECONDS starts closers
  while :; do
    if [ "$(grep -cE '(READY|NOT READY): ' "$GATEWAY_LOG" 2>/dev/null || true)" -gt "$before" ]; then
      return 0
    fi
    gateway_supervised || { echo "hosted-smoke: gateway exited before its readiness verdict" >&2; return 1; }
    starts=$(log_count 'installing ACP adapters into')
    closers=$(log_count 'ACP adapter install into')
    if [ "$starts" -gt "$closers" ]; then
      waited_from=$SECONDS
    elif [ $((SECONDS - waited_from)) -ge 60 ]; then
      echo "hosted-smoke: no readiness verdict within 60 s of the last adapter activity" >&2
      return 1
    fi
    sleep 0.5
  done
}

adapter_install_failed() { grep -q 'ACP adapter install into .* failed' "$GATEWAY_LOG"; }

install_traps

PHASE=identity
record_identity

# 1. A fresh org: first boot creates the base and its identity repository, and installs
#    the pinned ACP adapters itself (Gateway.install_local_adapters/1). It cannot run a
#    turn yet; its verdict only marks that boot has settled.
PHASE=first-boot
note "phase $PHASE"
boot_gateway
await_verdict 0
if adapter_install_failed; then echo "hosted-smoke: ACP adapter install failed" >&2; exit 1; fi

# 2. The owner. On an empty local org the first user is created directly and becomes
#    admin by the cold-start rule; feature_smoke drives admin verbs as this user.
PHASE=owner
note "phase $PHASE"
require_supervised
"$CLI" add-user "$OWNER" --admin > "$PRIVATE/add-user.out" 2>&1

# 3. Provider credentials, through the only sanctioned path: the key on stdin, never
#    argv, validated against the provider before it is banked as an api_key-kind row.
PHASE=onboard
note "phase $PHASE"
require_supervised
printf '%s' "$anthropic_key" | "$CLI" onboard anthropic --api-key --as-user "$OWNER" > "$PRIVATE/onboard-anthropic.out" 2>&1
printf '%s' "$openai_key" | "$CLI" onboard openai --api-key --as-user "$OWNER" > "$PRIVATE/onboard-openai.out" 2>&1
unset anthropic_key openai_key

# 4. Org law and archetypes: the shipped agentic-engineering kungfu carries the
#    verification statutes and the coder/reviewer-code archetypes the smoke needs.
PHASE=learn
note "phase $PHASE"
require_supervised
"$CLI" learn agentic-engineering --as-user "$OWNER" > "$PRIVATE/learn.out" 2>&1

# 5. Rules load once at boot: restart onto the provisioned org.
PHASE=restart
note "phase $PHASE"
stop_gateway
verdicts_so_far=$(grep -cE '(READY|NOT READY): ' "$GATEWAY_LOG" || true)
boot_gateway
await_verdict "$verdicts_so_far"

# 6. The unchanged full matrix: every registered leg, both real harnesses, each with its
#    own credential preflight. Raw output stays private; only selected lines publish.
PHASE=smoke
note "phase $PHASE"
require_supervised
set +e
env TIGHTBEAM_BASE_DIR="$BASE" TIGHTBEAM_SMOKE_OWNER="$OWNER" \
  mix run --no-start scripts/feature_smoke.exs > "$PRIVATE/smoke.out" 2>&1
SMOKE_RC=$?
set -e
sh "$REPO/scripts/hosted_smoke_evidence.sh" < "$PRIVATE/smoke.out" > "$SMOKE_EVIDENCE_DIR/smoke-results.txt"
cat "$SMOKE_EVIDENCE_DIR/smoke-results.txt"
PHASE=done
[ "$SMOKE_RC" = 0 ]
