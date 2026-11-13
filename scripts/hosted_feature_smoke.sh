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
# Exit status 0 (verdict PASS) needs ALL of: feature_smoke.exs exited 0, both registered
# legs reported their completion line at full parity, the gateway and every process it
# owned are confirmed gone, and RUN_ROOT (banked keys, minted bearers) is removed. Every
# other path exits non-zero and records the phase reached and why teardown, if it did,
# fell short. Failure detail stays in RUN_ROOT/private on the runner; nothing retries.
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
GATEWAY_PID=
GATEWAY_START=
STOP_REASON=
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

gateway_alive() {
  local st
  [ -n "$GATEWAY_PID" ] || return 1
  st=$(proc_status "$GATEWAY_PID" "$GATEWAY_START")
  [ "$st" = alive ] || [ "$st" = unknown ]
}

# Same bounds as Tightbeam.ClientE2E.LegGateway (boot readiness 60 s, exit after SIGTERM
# 30 s, descendant reap 15 s, port release 30 s), without its MIX_ENV=test registry: the
# gateway under test runs the default environment, whose registry is exactly the real
# harnesses this smoke must cover. setsid(1) makes it the leader of its own session and
# process group (no fork: a background job of a non-interactive shell is not a group
# leader), so everything it spawns can be found and signalled as one group.
boot_gateway() {
  local f
  if version_answers; then
    echo "hosted-smoke: something already answers port $PORT; refusing to boot over it" >&2
    return 1
  fi
  (
    exec setsid env TIGHTBEAM_BASE_DIR="$BASE" TIGHTBEAM_PORT="$PORT" TIGHTBEAM_EFFORT_CHECKIN_HORIZON_MS=2500 \
      mix run --no-halt --no-start -e \
      'Application.put_env(:tightbeam, :autostart, true); Application.put_env(:tightbeam, :base_dir, System.fetch_env!("TIGHTBEAM_BASE_DIR")); Application.put_env(:tightbeam, :port, String.to_integer(System.fetch_env!("TIGHTBEAM_PORT"))); Application.ensure_all_started(:tightbeam)' \
      >> "$GATEWAY_LOG" 2>&1
  ) &
  GATEWAY_PID=$!
  # The start time is fixed at fork and survives every exec in the chain, so it is the
  # identity every later signal is checked against.
  GATEWAY_START=$(proc_start "$GATEWAY_PID") || { echo "hosted-smoke: cannot read the gateway's identity" >&2; return 1; }
  local deadline=$((SECONDS + 60))
  until version_answers; do
    gateway_alive || { echo "hosted-smoke: gateway exited during boot" >&2; return 1; }
    [ "$SECONDS" -lt "$deadline" ] || { echo "hosted-smoke: /version did not answer within 60 s" >&2; return 1; }
    sleep 0.5
  done
  # The process that answers must be the group leader we launched, or nothing below can
  # account for what it owns.
  f=$(proc_fields "$GATEWAY_PID") || { echo "hosted-smoke: cannot read the gateway's process group" >&2; return 1; }
  # shellcheck disable=SC2086
  set -- $f
  [ "$2" = "$GATEWAY_PID" ] && [ "$3" = "$GATEWAY_PID" ] || {
    echo "hosted-smoke: the gateway is not the leader of its own process group" >&2
    return 1
  }
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
    gateway_alive || { echo "hosted-smoke: gateway exited before its readiness verdict" >&2; return 1; }
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

# Stop the gateway and everything it owns, or say exactly why that could not be shown.
# Success means all of these:
#   - the recorded gateway process was seen alive, signalled, and seen to exit;
#   - its process group emptied, observed without a break from that exit onward;
#   - every descendant captured before the signal is gone (a pid now holding a different
#     process proves ours ended; such a pid is never signalled);
#   - the port no longer answers. A silent port proves nothing about a child tree.
# A gateway that had already exited before this stop began cannot be accounted for: its
# group number may since have been reused, so nothing is signalled and the stop fails.
# An unreadable process counts as alive. There is no SIGKILL and no second attempt.
# The FIRST reason a stop fell short is the one reported; the exit handler's later
# attempt must not overwrite it.
stop_fail() { [ -n "$STOP_REASON" ] || STOP_REASON=$1; }

stop_gateway() {
  local tree st deadline pid start remaining members
  [ -n "$GATEWAY_PID" ] || return 0
  st=$(proc_status "$GATEWAY_PID" "$GATEWAY_START")
  case "$st" in
    alive) ;;
    unknown) stop_fail gateway_identity_unknown; return 1 ;;
    gone | reused) stop_fail gateway_exited_unobserved; return 1 ;;
  esac

  # Captured BEFORE the signal: children reparent once their parent exits.
  tree=$(capture_tree "$GATEWAY_PID")
  kill -TERM "$GATEWAY_PID" 2>/dev/null || true
  deadline=$((SECONDS + 30))
  while gateway_alive && [ "$SECONDS" -lt "$deadline" ]; do sleep 0.25; done
  if gateway_alive; then stop_fail gateway_outlived_sigterm; return 1; fi
  # Collect our child's exit status (bash may already have reaped it).
  wait "$GATEWAY_PID" 2>/dev/null || true

  # One group signal, immediately. The group number stays in use for as long as any
  # member lives, so members found now are ours unless, in the moment since the leader
  # exited, every member died AND the number was handed to a new group. That residual
  # window is the only one left, and a stranger seen later only ever fails the stop
  # (nothing is signalled after this point). Members that left the group are signalled
  # one by one, each only after its recorded start time is confirmed again.
  members=$(group_members "$GATEWAY_PID")
  if [ -n "$members" ]; then kill -TERM -- "-$GATEWAY_PID" 2>/dev/null || true; fi
  while read -r pid start; do
    [ -n "$pid" ] || continue
    if [ "$(proc_status "$pid" "$start")" = alive ]; then kill -TERM "$pid" 2>/dev/null || true; fi
  done <<< "$tree"

  # From here on only observe. The group is done at its first empty scan and never
  # scanned again; captured descendants are checked by identity until all are gone.
  deadline=$((SECONDS + 15))
  while :; do
    remaining=
    if [ -n "$members" ]; then
      members=$(group_members "$GATEWAY_PID")
      remaining=$members
    fi
    while read -r pid start; do
      [ -n "$pid" ] || continue
      st=$(proc_status "$pid" "$start")
      if [ "$st" = alive ] || [ "$st" = unknown ]; then remaining="$remaining $pid"; fi
    done <<< "$tree"
    [ -n "${remaining//[[:space:]]/}" ] || break
    [ "$SECONDS" -lt "$deadline" ] || { stop_fail owned_process_survived; return 1; }
    sleep 0.25
  done

  deadline=$((SECONDS + 30))
  while version_answers && [ "$SECONDS" -lt "$deadline" ]; do sleep 0.25; done
  if version_answers; then stop_fail port_still_answering; return 1; fi
  GATEWAY_PID=
}

finish() {
  local rc=$? stopped=yes removed=no verdict
  trap - EXIT
  set +e
  stop_gateway || stopped=no
  # The run root holds the banked provider keys and every minted bearer. It is removed
  # only after a confirmed stop (deleting state under a live gateway is worse than
  # keeping it), and removal is itself confirmed.
  if [ "$stopped" = yes ]; then
    rm -rf "$SMOKE_RUN_ROOT"
    if [ ! -e "$SMOKE_RUN_ROOT" ] && [ ! -L "$SMOKE_RUN_ROOT" ]; then removed=yes; fi
  fi

  verdict=$(smoke_verdict "${SMOKE_RC:-}" "$PHASE" "$stopped" "$removed" "$SMOKE_EVIDENCE_DIR/smoke-results.txt")
  [ "$verdict" = PASS ] && rc=0
  [ "$verdict" = PASS ] || { [ "$rc" = 0 ] && rc=1; }

  printf '{"verdict":"%s","phase_reached":"%s","smoke_exit":"%s","gateway_stopped":"%s","stop_reason":"%s","run_root_removed":"%s"}\n' \
    "$verdict" "$PHASE" "${SMOKE_RC:-not_run}" "$stopped" "${STOP_REASON:-none}" "$removed" > "$SMOKE_EVIDENCE_DIR/summary.json"
  note "verdict=$verdict phase=$PHASE smoke_exit=${SMOKE_RC:-not_run} gateway_stopped=$stopped stop_reason=${STOP_REASON:-none} run_root_removed=$removed"
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
