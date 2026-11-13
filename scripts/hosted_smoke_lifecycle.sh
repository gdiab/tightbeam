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
# SMOKE_EVIDENCE_DIR. Callers may set SUP_TERM_WAIT / SUP_SWEEP_WAIT (the supervisor's
# bounds; LegGateway's 30 and 15 by default) and SUP_RECEIPT_WAIT (default 10 s).
#
# SUP_STATE, and who owns the gateway and its stop in each:
#   none        nothing launched (or the last gateway is confirmed stopped and released)
#   running     the supervisor holds the gateway's pidfd (DIR/owned); no stop sent
#   sending     transient, inside the send's critical section only (see below)
#   sent        exactly one "stop" was written to the FIFO; receipt not yet observed
#   requested   the supervisor has acknowledged the request (DIR/received >= 1) or its
#               stop has begun (DIR/stopping) or it has already reported; it owns the
#               stop and will finish it within its own bounds
#   stopped     the supervisor reported "stopped": gateway and whole tree gone
#   stop_failed terminal: anything else. Never sent again, never waited on again.
#
# Delivery is not intent. "sent" means the write returned success; only the supervisor's
# own DIR/received count, its DIR/stopping marker or its result show that a stop is
# actually under way. Every wait is bounded: receipt by SUP_RECEIPT_WAIT, collection by
# the supervisor's own two bounds plus a 10 s margin. A bound that expires is a truthful
# terminal failure, never a pass: the gateway may still be running, and the run root is
# kept for the VM's decommissioning (the backstop, not the lifecycle).

SUP_STATE=none
STOP_REASON=
INTERRUPTED=
IN_CRITICAL=
IN_FINISH=
PENDING_EXIT=

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
  rm -f "$dir/control" "$dir/owned" "$dir/received" "$dir/stopping" "$dir/result"
  mkfifo -m 600 "$dir/control"
  python3 "$SUPERVISOR" --dir "$dir" --log "$log" \
    --term-wait "${SUP_TERM_WAIT:-30}" --sweep-wait "${SUP_SWEEP_WAIT:-15}" -- "$@" \
    > "$dir/supervisor.out" 2>&1 &
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

# The single delivery attempt: one "stop" line written to the FIFO. A read-write open of a
# FIFO never blocks on Linux, and printf is an ordinary builtin, so a failed redirection
# or write returns non-zero here instead of ending the shell. Kept separate so tests can
# wrap it to inject failures and signals at the delivery boundary.
send_stop_request() {
  [ -p "$SUP_DIR/control" ] || return 1
  printf 'stop\n' 1<>"$SUP_DIR/control"
}

# Has the supervisor taken the stop? Its own receipt count, its stopping marker, or its
# result are authoritative; the shell's write is not.
stop_acknowledged() {
  [ -s "$SUP_DIR/stopping" ] || [ -s "$SUP_DIR/result" ] \
    || { [ -s "$SUP_DIR/received" ] && [ "$(cat "$SUP_DIR/received")" -ge 1 ]; }
}

# Act on a signal that arrived inside the critical section, now that the state is true.
deferred_exit() {
  if [ -n "$PENDING_EXIT" ] && [ -z "$IN_FINISH" ]; then exit "$PENDING_EXIT"; fi
}

# The one stop of the current gateway. The send happens at most once per gateway, inside
# a critical section in which a signal is recorded but not acted on, so the state always
# says whether the write happened before any trap can run the EXIT handler. Nothing in
# the section can trip `set -e`. Later calls (the EXIT trap included) never send again:
# they continue from the recorded state, with bounded waits.
stop_gateway() {
  local deadline
  case "$SUP_STATE" in
    none | stopped) return 0 ;;
    stop_failed) return 1 ;;
    sending)
      # Unreachable by construction (the section defers signals and cannot fail out);
      # if ever seen, whether the write happened is unknown, so never send again.
      SUP_STATE=stop_failed
      stop_fail request_delivery_uncertain
      return 1
      ;;
    running)
      if [ -s "$SUP_DIR/result" ]; then
        # The supervisor has already reported (an early exit, a lost owner): nothing to ask.
        SUP_STATE=requested
      else
        IN_CRITICAL=1
        SUP_STATE=sending
        if send_stop_request; then SUP_STATE=sent; else SUP_STATE=stop_failed; fi
        IN_CRITICAL=
        if [ "$SUP_STATE" = stop_failed ]; then stop_fail request_not_delivered; fi
        deferred_exit
        [ "$SUP_STATE" = sent ] || return 1
      fi
      ;;
  esac

  if [ "$SUP_STATE" = sent ]; then
    deadline=$((SECONDS + ${SUP_RECEIPT_WAIT:-10}))
    until stop_acknowledged; do
      if ! supervisor_alive || [ "$SECONDS" -ge "$deadline" ]; then
        stop_acknowledged && break
        SUP_STATE=stop_failed
        if supervisor_alive; then stop_fail request_unacknowledged; else stop_fail supervisor_gone_before_receipt; fi
        return 1
      fi
      sleep 0.1
    done
    SUP_STATE=requested
  fi

  # requested: the supervisor owns the stop and finishes it within its own bounds.
  deadline=$((SECONDS + ${SUP_TERM_WAIT:-30} + ${SUP_SWEEP_WAIT:-15} + 10))
  while [ ! -s "$SUP_DIR/result" ] && supervisor_alive && [ "$SECONDS" -lt "$deadline" ]; do
    sleep 0.2
  done
  if [ ! -s "$SUP_DIR/result" ]; then
    SUP_STATE=stop_failed
    if supervisor_alive; then stop_fail supervisor_unresponsive; else stop_fail supervisor_reported_nothing; fi
    return 1
  fi
  local result
  result=$(cat "$SUP_DIR/result")
  if [ "$result" = stopped ]; then
    SUP_STATE=stopped
    return 0
  fi
  SUP_STATE=stop_failed
  stop_fail "${result// /:}"
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
  IN_FINISH=1
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
# status, which finish_run then refuses to report as success. Inside the stop request's
# critical section the exit is deferred until the state records whether the write
# happened (deferred_exit); it is never dropped.
on_signal() {
  INTERRUPTED=yes
  if [ -n "$IN_CRITICAL" ]; then
    [ -n "$PENDING_EXIT" ] || PENDING_EXIT=$1
    return 0
  fi
  exit "$1"
}

install_traps() {
  trap finish_run EXIT
  trap 'on_signal 129' HUP
  trap 'on_signal 130' INT
  trap 'on_signal 143' TERM
}
