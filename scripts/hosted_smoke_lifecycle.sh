# Gateway ownership, single-attempt stop, verdict and exit handling for
# scripts/hosted_feature_smoke.sh. Sourced, never executed. Linux only: the hosted route
# runs on ubuntu-24.04, and scripts/hosted_smoke_supervisor.py needs pidfds (Linux 5.3+)
# and PR_SET_CHILD_SUBREAPER.
#
# The shell never signals a process by number. Each gateway run is owned by one
# supervisor (hosted_smoke_supervisor.py), which is the subreaper of the gateway's whole
# tree and signals only through pidfds. The shell talks to it through a FIFO ("stop") and
# learns the outcome from the supervisor's one-line result file and exit status.
#
# Globals: SUPERVISOR (path to the supervisor), SUP_STATE (none|running|stopped|
# stop_failed), SUP_PID, SUP_CONTROL, SUP_RESULT, STOP_REASON (the FIRST reason a stop fell
# short), INTERRUPTED, PHASE, SMOKE_RC, SMOKE_RUN_ROOT, SMOKE_EVIDENCE_DIR. Callers may set
# SUP_TERM_WAIT / SUP_SWEEP_WAIT (seconds; defaults are LegGateway's 30 and 15).

SUP_STATE=none
STOP_REASON=
INTERRUPTED=

stop_fail() { [ -n "$STOP_REASON" ] || STOP_REASON=$1; }

# Start one supervised gateway. $1 is a private directory for this run's control FIFO and
# result file, $2 the gateway log; the rest is the gateway argv.
start_gateway_supervised() {
  local dir=$1 log=$2
  shift 2
  [ "$SUP_STATE" != running ] || { echo "hosted-smoke: a gateway is already supervised" >&2; return 1; }
  SUP_CONTROL="$dir/control"
  SUP_RESULT="$dir/result"
  mkdir -p "$dir"
  rm -f "$SUP_CONTROL" "$SUP_RESULT"
  mkfifo -m 600 "$SUP_CONTROL"
  python3 "$SUPERVISOR" --control "$SUP_CONTROL" --result "$SUP_RESULT" --log "$log" \
    --term-wait "${SUP_TERM_WAIT:-30}" --sweep-wait "${SUP_SWEEP_WAIT:-15}" -- "$@" &
  SUP_PID=$!
  SUP_STATE=running
}

# True while the supervisor has not reported an outcome, i.e. its gateway is still owned.
gateway_supervised() { [ "$SUP_STATE" = running ] && [ ! -s "$SUP_RESULT" ]; }

# The one stop of the current gateway. Never repeated: a failed stop stays failed, and
# the first reason is kept. The shell writes "stop" and waits for the supervisor, whose
# own waits are bounded (term + sweep), then reads its result.
stop_gateway() {
  local fd result
  case "$SUP_STATE" in
    none | stopped) return 0 ;;
    stop_failed) return 1 ;;
  esac
  # Read-write open of a FIFO never blocks on Linux, even if the reader is gone.
  exec {fd}<>"$SUP_CONTROL"
  printf 'stop\n' >&"$fd" 2>/dev/null || true
  exec {fd}>&-
  wait "$SUP_PID" 2>/dev/null
  result=$(cat "$SUP_RESULT" 2>/dev/null || true)
  case "$result" in
    stopped)
      SUP_STATE=stopped
      return 0
      ;;
    "")
      SUP_STATE=stop_failed
      stop_fail supervisor_reported_nothing
      return 1
      ;;
    *)
      SUP_STATE=stop_failed
      stop_fail "${result// /:}"
      return 1
      ;;
  esac
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
