#!/usr/bin/env bash
# Live feature smoke, BOTH real harnesses, on a fresh org that exists only on this
# disposable machine. Driven by .github/workflows/live-feature-smoke.yml on a fresh
# GitHub-hosted VM; run from the root of the exact candidate checkout after it is built.
#
# The isolation boundary is the VM, not anything in this script. The org, its database,
# its minted bearers and the provider keys it banks live under RUN_ROOT on that VM's
# disk. Each GitHub-hosted job runs on a new, ephemeral VM; this script still removes
# RUN_ROOT itself once its gateway is confirmed gone. It never copies anything from
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
# Exit status is the smoke's: 0 only when feature_smoke.exs exited 0 AND both registered
# legs reported their completion line. Every other path exits non-zero and says which
# phase it reached; the reason's detail stays in RUN_ROOT/private on the runner.
set -euo pipefail
umask 077

: "${SMOKE_RUN_ROOT:?}" "${SMOKE_EVIDENCE_DIR:?}" "${SMOKE_WORKFLOW_SHA:?}"
: "${SMOKE_PROVIDER_ANTHROPIC:?}" "${SMOKE_PROVIDER_OPENAI:?}"
: "${TIGHTBEAM_SMOKE_MODEL_CLAUDE:?}" "${TIGHTBEAM_SMOKE_EFFORT_CLAUDE:?}"
: "${TIGHTBEAM_SMOKE_MODEL_CODEX:?}" "${TIGHTBEAM_SMOKE_EFFORT_CODEX:?}"

REPO=$(pwd -P)
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
GATEWAY_PID=
GATEWAY_CMD=
SMOKE_RC=

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

gateway_ours() {
  [ -n "$GATEWAY_PID" ] && [ "$(ps -o args= -p "$GATEWAY_PID" 2>/dev/null || true)" = "$GATEWAY_CMD" ]
}

descendants_of() {
  local pid=$1 child
  for child in $(ps -o pid= --ppid "$pid" 2>/dev/null || true); do
    printf '%s\n' "$child"
    descendants_of "$child"
  done
}

# Same lifecycle and bounds as Tightbeam.ClientE2E.LegGateway (boot readiness 60 s,
# exit after SIGTERM 30 s, descendant reap 15 s), without its MIX_ENV=test registry:
# the gateway under test runs the default environment, whose registry is exactly the
# real harnesses this smoke must cover.
boot_gateway() {
  if version_answers; then
    echo "hosted-smoke: something already answers port $PORT; refusing to boot over it" >&2
    return 1
  fi
  (
    exec env TIGHTBEAM_BASE_DIR="$BASE" TIGHTBEAM_PORT="$PORT" TIGHTBEAM_EFFORT_CHECKIN_HORIZON_MS=2500 \
      mix run --no-halt --no-start -e \
      'Application.put_env(:tightbeam, :autostart, true); Application.put_env(:tightbeam, :base_dir, System.fetch_env!("TIGHTBEAM_BASE_DIR")); Application.put_env(:tightbeam, :port, String.to_integer(System.fetch_env!("TIGHTBEAM_PORT"))); Application.ensure_all_started(:tightbeam)' \
      >> "$GATEWAY_LOG" 2>&1
  ) &
  GATEWAY_PID=$!
  local deadline=$((SECONDS + 60))
  until version_answers; do
    kill -0 "$GATEWAY_PID" 2>/dev/null || { echo "hosted-smoke: gateway exited during boot" >&2; return 1; }
    [ "$SECONDS" -lt "$deadline" ] || { echo "hosted-smoke: /version did not answer within 60 s" >&2; return 1; }
    sleep 0.5
  done
  # The exec chain (sh → mix → elixir → beam.smp) rewrites argv while it boots, so the
  # identity used to gate every later signal is read only once the port answers.
  GATEWAY_CMD=$(ps -o args= -p "$GATEWAY_PID")
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
    gateway_ours || { echo "hosted-smoke: gateway exited before its readiness verdict" >&2; return 1; }
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

stop_gateway() {
  local tree pid deadline
  gateway_ours || { GATEWAY_PID=; return 0; }
  # Capture the tree BEFORE signalling: adapters reparent once their parent is gone.
  tree=$(descendants_of "$GATEWAY_PID")
  kill -TERM "$GATEWAY_PID" 2>/dev/null || true
  deadline=$((SECONDS + 30))
  while gateway_ours && [ "$SECONDS" -lt "$deadline" ]; do sleep 0.25; done
  if gateway_ours; then
    echo "hosted-smoke: gateway pid $GATEWAY_PID outlived SIGTERM by 30 s; left for VM teardown" >&2
    return 1
  fi
  for pid in $tree; do kill -TERM "$pid" 2>/dev/null || true; done
  deadline=$((SECONDS + 15))
  for pid in $tree; do
    while kill -0 "$pid" 2>/dev/null && [ "$SECONDS" -lt "$deadline" ]; do sleep 0.25; done
  done
  deadline=$((SECONDS + 30))
  while version_answers && [ "$SECONDS" -lt "$deadline" ]; do sleep 0.25; done
  if version_answers; then
    echo "hosted-smoke: port $PORT still answers after the gateway exited" >&2
    return 1
  fi
  GATEWAY_PID=
}

finish() {
  local rc=$? stopped=yes removed=no verdict
  trap - EXIT
  set +e
  stop_gateway || stopped=no
  # The org directory holds the banked provider keys and every minted bearer. Remove
  # it only once its gateway is confirmed gone (removing state under a live gateway is
  # worse than leaving it). Either way the job's VM is ephemeral and is not reused.
  if [ "$stopped" = yes ] && rm -rf "$SMOKE_RUN_ROOT"; then removed=yes; fi

  if [ "${SMOKE_RC:-}" = 0 ] && [ "$rc" = 0 ] && grep -qx 'feature-smoke leg claude: [0-9]* checks PASS' "$SMOKE_EVIDENCE_DIR/smoke-results.txt" 2>/dev/null \
     && grep -qx 'feature-smoke leg codex: [0-9]* checks PASS' "$SMOKE_EVIDENCE_DIR/smoke-results.txt" 2>/dev/null \
     && grep -q '(every registered leg — full parity)$' "$SMOKE_EVIDENCE_DIR/smoke-results.txt" 2>/dev/null; then
    verdict=PASS
  else
    verdict=FAIL
    [ "$rc" = 0 ] && rc=1
  fi

  printf '{"verdict":"%s","phase_reached":"%s","smoke_exit":"%s","gateway_stopped":"%s","run_root_removed":"%s"}\n' \
    "$verdict" "$PHASE" "${SMOKE_RC:-not_run}" "$stopped" "$removed" > "$SMOKE_EVIDENCE_DIR/summary.json"
  note "verdict=$verdict phase=$PHASE smoke_exit=${SMOKE_RC:-not_run} gateway_stopped=$stopped run_root_removed=$removed"
  exit "$rc"
}
trap finish EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

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
"$CLI" add-user "$OWNER" --admin > "$PRIVATE/add-user.out" 2>&1

# 3. Provider credentials, through the only sanctioned path: the key on stdin, never
#    argv, validated against the provider before it is banked as an api_key-kind row.
PHASE=onboard
note "phase $PHASE"
printf '%s' "$anthropic_key" | "$CLI" onboard anthropic --api-key --as-user "$OWNER" > "$PRIVATE/onboard-anthropic.out" 2>&1
printf '%s' "$openai_key" | "$CLI" onboard openai --api-key --as-user "$OWNER" > "$PRIVATE/onboard-openai.out" 2>&1
unset anthropic_key openai_key

# 4. Org law and archetypes: the shipped agentic-engineering kungfu carries the
#    verification statutes and the coder/reviewer-code archetypes the smoke needs.
PHASE=learn
note "phase $PHASE"
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
set +e
env TIGHTBEAM_BASE_DIR="$BASE" TIGHTBEAM_SMOKE_OWNER="$OWNER" \
  mix run --no-start scripts/feature_smoke.exs > "$PRIVATE/smoke.out" 2>&1
SMOKE_RC=$?
set -e
sh "$REPO/scripts/hosted_smoke_evidence.sh" < "$PRIVATE/smoke.out" > "$SMOKE_EVIDENCE_DIR/smoke-results.txt"
cat "$SMOKE_EVIDENCE_DIR/smoke-results.txt"
PHASE=done
[ "$SMOKE_RC" = 0 ]
