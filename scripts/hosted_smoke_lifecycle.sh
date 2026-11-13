# Process identity, owned-process sweep and verdict for scripts/hosted_feature_smoke.sh.
# Sourced, never executed. Linux /proc only: the hosted route runs on ubuntu-24.04.
#
# IDENTITY. A process is (pid, start time), the start time read from field 22 of
# /proc/<pid>/stat. Unlike argv, it survives the exec chain sh → mix → elixir → beam.smp,
# and a recycled pid carries a different start time. Every answer below is one of:
#   gone     no such pid, or our process is a zombie (it has exited)
#   reused   the pid exists with a DIFFERENT start time: ours ended; never signal it
#   alive    the pid still holds the process we recorded
#   unknown  /proc could not be read consistently; callers must treat this as alive
#
# OWNERSHIP. The gateway is launched with setsid(1), so it leads a new session and
# process group whose id is its own pid. Everything it spawns inherits that group unless
# it deliberately leaves, and the tree captured before the stop covers those that left.

# Print "state pgrp session starttime" for a pid, or nothing if it cannot be read.
proc_fields() {
  local stat rest
  stat=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
  # The command name is parenthesised and may itself contain spaces and parentheses;
  # everything after its LAST ") " is space-separated.
  rest=${stat##*) }
  # shellcheck disable=SC2086
  set -- $rest
  [ $# -ge 20 ] || return 1
  printf '%s %s %s %s\n' "$1" "$3" "$4" "${20}"
}

proc_start() {
  local f
  f=$(proc_fields "$1") || return 1
  printf '%s\n' "${f##* }"
}

proc_status() {
  local pid=$1 expected=$2 f state start
  if [ ! -e "/proc/$pid" ]; then echo gone; return; fi
  if ! f=$(proc_fields "$pid"); then
    if [ ! -e "/proc/$pid" ]; then echo gone; else echo unknown; fi
    return
  fi
  state=${f%% *}
  start=${f##* }
  if [ "$start" != "$expected" ]; then echo reused; return; fi
  if [ "$state" = Z ]; then echo gone; return; fi
  echo alive
}

# Live members of process group $1, excluding zombies, one "pid start" per line. A process
# that vanishes while being read is skipped: /proc/<pid>/stat is readable for every
# process, so a failed read means it no longer exists.
#
# A group id is the leader's pid, and the kernel does not hand that number out again while
# any member of the group is alive. So members seen without a break since the leader was
# watched exiting are ours. Once a scan finds none, the number is free, and anything seen
# under it later may belong to someone else: callers stop at the first empty scan.
group_members() {
  local group=$1 dir pid f state pgrp start
  for dir in /proc/[0-9]*; do
    pid=${dir#/proc/}
    f=$(proc_fields "$pid") || continue
    # shellcheck disable=SC2086
    set -- $f
    state=$1 pgrp=$2 start=$4
    [ "$pgrp" = "$group" ] && [ "$state" != Z ] && printf '%s %s\n' "$pid" "$start"
  done
  return 0
}

# "pid start" for every descendant of $1, captured BEFORE any signal: children reparent
# once their parent exits, so the tree cannot be rebuilt afterwards.
capture_tree() {
  local pid=$1 child start
  for child in $(ps -o pid= --ppid "$pid" 2>/dev/null || true); do
    start=$(proc_start "$child") || continue
    printf '%s %s\n' "$child" "$start"
    capture_tree "$child"
  done
}

# The overall verdict. PASS needs every required smoke assertion AND a confirmed stop of
# the gateway and everything it owned AND removal of the run root, which holds the banked
# provider keys and every minted bearer. The VM's later disposal is a backstop, not a
# substitute: a run that could not prove its own teardown did not pass.
#   $1 smoke exit status ("" if the smoke never ran)   $2 phase reached
#   $3 gateway_stopped (yes|no)   $4 run_root_removed (yes|no)   $5 selected results file
smoke_verdict() {
  local smoke_rc=$1 phase=$2 stopped=$3 removed=$4 results=$5
  if [ "$smoke_rc" = 0 ] && [ "$phase" = done ] && [ "$stopped" = yes ] && [ "$removed" = yes ] \
     && grep -qx 'feature-smoke leg claude: [0-9][0-9]* checks PASS' "$results" 2>/dev/null \
     && grep -qx 'feature-smoke leg codex: [0-9][0-9]* checks PASS' "$results" 2>/dev/null \
     && grep -q '(every registered leg — full parity)$' "$results" 2>/dev/null; then
    echo PASS
  else
    echo FAIL
  fi
}
