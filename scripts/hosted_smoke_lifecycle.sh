# Gateway ownership, single-attempt stop, verdict and exit handling for
# scripts/hosted_feature_smoke.sh. Sourced, never executed. Linux only: the hosted route
# runs on ubuntu-24.04, and scripts/hosted_smoke_supervisor.py needs pidfds (Linux 5.3+)
# and PR_SET_CHILD_SUBREAPER.
#
# The shell never signals a process. Each gateway run is owned by one supervisor
# (hosted_smoke_supervisor.py), the subreaper of the gateway's whole tree, which signals
# only through pidfds. The shell asks it to stop through a FIFO ("stop", at most once),
# learns the outcome from its one-line DIR/result, and judges its liveness from this
# shell's own job table.
#
# Globals: SUPERVISOR (path to the supervisor), SUP_STATE, SUP_PID, SUP_DIR, STOP_REASON
# (the FIRST lifecycle failure reason), INTERRUPTED, PHASE, SMOKE_RC, SMOKE_RUN_ROOT,
# SMOKE_EVIDENCE_DIR. Callers may set SUP_TERM_WAIT / SUP_SWEEP_WAIT (seconds; defaults
# are LegGateway's 30 and 15).
#
# SUP_STATE and who owns what:
#   none        nothing launched (or the last gateway is confirmed stopped and released)
#   running     the supervisor holds the gateway's pidfd (DIR/owned seen); no stop asked
#   requested   "stop" has been written ONCE; the outcome is not yet consumed
#   stopped     the supervisor reported "stopped": gateway and whole tree gone
#   stop_failed terminal: any other outcome, or ownership lost. Never stopped again.
# Every transition happens before control can leave the function: no command whose
# failure could unwind the shell under `set -e` runs between a request and its state.

SUP_STATE=none
STOP_REASON=
INTERRUPTED=

stop_fail() { [ -n "$STOP_REASON" ] || STOP_REASON=$1; }

# Liveness of the supervisor, from this shell's own job table: bash marks its background
# job done when it reaps it, so this never confuses the supervisor with a recycled pid.
supervisor_alive() { jobs -rp | grep -qx "$SUP_PID"; }

# Start one supervised gateway and wait for the control handoff. $1 is a private directory
# for this boot, $2 the gateway log; the rest is the gateway argv. Returns 0 only once the
# supervisor holds the gateway's pidfd (DIR/owned). If the supervisor reports
# control_unavailable, the gateway was never started; any other outcome before the
# handoff is a terminal failure.
start_gateway_supervised() {
  local dir=$1 log=$2 result
  shift 2
  [ "$SUP_STATE" = none ] || [ "$SUP_STATE" = stopped ] || {
    stop_fail "start_while_${SUP_STATE}"
    return 1
  }
  SUP_DIR=$dir
  mkdir -p "$dir"
  rm -f "$dir/control" "$dir/owned" "$dir/result" "$dir/requests"
  mkfifo -m 600 "$dir/control"
  python3 "$SUPERVISOR" --dir "$dir" --log "$log" \
    --term-wait "${SUP_TERM_WAIT:-30}" --sweep-wait "${SUP_SWEEP_WAIT:-15}" -- "$@" &
  SUP_PID=$!
  while [ ! -e "$dir/owned" ] && [ ! -s "$dir/result" ] && supervisor_alive; do sleep 0.1; done
  if [ -e "$dir/owned" ]; then
    SUP_STATE=running
    return 0
  fi
  result=$(cat "$dir/result" 2>/dev/null || true)
  case "$result" in
    control_unavailable*) SUP_STATE=none ;;
    *) SUP_STATE=stop_failed ;;
  esac
  result=${result// /:}
  stop_fail "start:${result:-supervisor_exited_without_result}"
  return 1
}

# True only while a live supervisor still owns a gateway it has not reported on.
gateway_supervised() {
  [ "$SUP_STATE" = running ] && [ ! -s "$SUP_DIR/result" ] && supervisor_alive
}

# Refuse to start a phase that spends provider credit or exposes credentials unless the
# gateway is still owned; a lost owner becomes the terminal failure.
require_supervised() {
  gateway_supervised && return 0
  if [ "$SUP_STATE" = running ]; then
    SUP_STATE=stop_failed
    stop_fail "owner_lost:$(tr ' ' ':' < "$SUP_DIR/result" 2>/dev/null || echo no_result)"
  fi
  echo "hosted-smoke: the gateway is no longer owned by its supervisor; refusing the next phase" >&2
  return 1
}

# The one stop of the current gateway. "stop" is written at most once per gateway (the
# request is logged to DIR/requests); a later call, from the EXIT trap or anywhere else,
# only collects the outcome. Waiting is guarded so that `set -e` cannot unwind the shell
# between the request and the state that records it.
stop_gateway() {
  local fd result wrc
  case "$SUP_STATE" in
    none | stopped) return 0 ;;
    stop_failed) return 1 ;;
    running)
      SUP_STATE=requested
      # A supervisor that has already reported (an early exit, a lost owner) is only
      # collected; there is nothing left to ask.
      if [ ! -s "$SUP_DIR/result" ]; then
        printf 'stop\n' >> "$SUP_DIR/requests"
        # A read-write open of a FIFO never blocks on Linux, even if the reader is gone.
        exec {fd}<>"$SUP_DIR/control"
        printf 'stop\n' >&"$fd" 2>/dev/null || true
        exec {fd}>&-
      fi
      ;;
    requested) ;;
  esac
  # Collect: wait until the supervisor is reaped (127: no such job left) or has reported.
  # A trapped signal ends a wait early (status > 128); the supervisor keeps its own bounded
  # course, so waiting again is not a second stop.
  while :; do
    wrc=0
    wait "$SUP_PID" 2>/dev/null || wrc=$?
    [ -s "$SUP_DIR/result" ] && ! supervisor_alive && break
    [ "$wrc" -eq 127 ] && break
    [ "$wrc" -le 128 ] && break
  done
  result=$(cat "$SUP_DIR/result" 2>/dev/null || true)
  if [ "$result" = stopped ]; then
    SUP_STATE=stopped
    return 0
  fi
  SUP_STATE=stop_failed
  if [ -n "$result" ]; then stop_fail "${result// /:}"; else stop_fail supervisor_reported_nothing; fi
  return 1
}

# The overall verdict. PASS needs ALL of:
#   $1 the enclosing script's own exit status is 0 (no error, no signal-forced exit);
#   $2 the smoke's exit status is 0;  $3 phase reached is "done";
#   $4 gateway_stopped=yes;  $5 run_root_removed=yes;  $6 no interruption was recorded;
#   $7 (the selected results) shows full parity and BOTH legs' completion lines.
# The VM's later decommissioning is a backstop, never a reason to pass.
smoke_verdict() {
  local enclosing=$1 smoke_rc=$2 phase=$3 stopped=$4 removed=$5 interrupted=$6 results=$7
  if [ "$enclosing" = 0 ] && [ "$smoke_rc" = 0 ] && [ "$phase" = done ] \
     && [ "$stopped" = yes ] && [ "$removed" = yes ] && [ -z "$interrupted" ] \
     && grep -qx 'feature-smoke leg claude: [0-9][0-9]* checks PASS' "$results" 2>/dev/null \
     && grep -qx 'feature-smoke leg codex: [0-9][0-9]* checks PASS' "$results" 2>/dev/null \
     && grep -q '(every registered leg — full parity)$' "$results" 2>/dev/null; then
    echo PASS
  else
    echo FAIL
  fi
}

# The EXIT handler. It runs once: a signal arriving while it runs is recorded, not acted
# on, so cleanup is neither cut short nor repeated. The incoming status is never rewritten
# to success; a FAIL with status 0 becomes 1.
finish_run() {
  local rc=$? stopped=yes removed=no verdict
  trap - EXIT
  trap 'INTERRUPTED=yes' HUP INT TERM
  set +e
  stop_gateway || stopped=no
  # The run root holds the banked provider keys and every minted bearer. It is removed
  # only after a confirmed stop, and its absence is confirmed.
  if [ "$stopped" = yes ]; then
    rm -rf "$SMOKE_RUN_ROOT"
    if [ ! -e "$SMOKE_RUN_ROOT" ] && [ ! -L "$SMOKE_RUN_ROOT" ]; then removed=yes; fi
  fi

  verdict=$(smoke_verdict "$rc" "${SMOKE_RC:-}" "$PHASE" "$stopped" "$removed" "$INTERRUPTED" \
    "$SMOKE_EVIDENCE_DIR/smoke-results.txt")
  if [ "$verdict" != PASS ] && [ "$rc" = 0 ]; then rc=1; fi

  printf '{"verdict":"%s","exit_status":"%s","phase_reached":"%s","smoke_exit":"%s","interrupted":"%s","gateway_stopped":"%s","stop_reason":"%s","run_root_removed":"%s"}\n' \
    "$verdict" "$rc" "$PHASE" "${SMOKE_RC:-not_run}" "${INTERRUPTED:-no}" "$stopped" "${STOP_REASON:-none}" "$removed" \
    > "$SMOKE_EVIDENCE_DIR/summary.json"
  printf 'hosted-smoke: verdict=%s exit=%s phase=%s smoke_exit=%s interrupted=%s gateway_stopped=%s stop_reason=%s run_root_removed=%s\n' \
    "$verdict" "$rc" "$PHASE" "${SMOKE_RC:-not_run}" "${INTERRUPTED:-no}" "$stopped" "${STOP_REASON:-none}" "$removed"
  exit "$rc"
}

# A signal in the main flow records the interruption and exits with the conventional
# status, which finish_run then refuses to report as success.
install_traps() {
  trap finish_run EXIT
  trap 'INTERRUPTED=yes; exit 129' HUP
  trap 'INTERRUPTED=yes; exit 130' INT
  trap 'INTERRUPTED=yes; exit 143' TERM
}
