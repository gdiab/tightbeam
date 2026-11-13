#!/usr/bin/env python3
"""Own one gateway process tree for the hosted live smoke, and stop all of it exactly once.

    python3 scripts/hosted_smoke_supervisor.py --control FIFO --result FILE --log FILE \
        [--term-wait SECONDS] [--sweep-wait SECONDS] -- GATEWAY_ARGV...

OWNERSHIP. This process marks itself a child subreaper (prctl(2) PR_SET_CHILD_SUBREAPER)
before it starts the gateway. Every process the gateway ever creates therefore stays
inside this process's tree: an orphan is reparented to its nearest living subreaper
ancestor, which is this process (or a subreaper below it), never to init. Leaving the
process group or the session (setsid, double fork) does not leave the tree. So when
waitpid(-1) reports ECHILD, the kernel is stating that no descendant is left.

IDENTITY. Nothing is signalled by number. The gateway and every orphan that reaches this
process are signalled through a pidfd, which refers to one process for its whole life
(pidfd_send_signal(2)). A pidfd is opened only for this process's own child, found as
such in /proc, and this process is that child's only reaper and reaps nothing between
finding it and opening the pidfd. So the pid cannot have been recycled
(pidfd_open(2), NOTES). Descendants still under a living parent are not signalled
directly. They reach this process, and are signalled, once their parent has exited.

ONE ATTEMPT. A stop is requested by the line "stop" on the control FIFO, or by SIGTERM,
SIGINT or SIGHUP to this process. It runs once:
  1. send SIGTERM to the gateway and wait --term-wait seconds for it to exit;
  2. sweep: SIGTERM each orphan once as it arrives, reap what exits, until ECHILD or
     --sweep-wait seconds.
There is no SIGKILL, no second signal and no second stop. If the gateway exits on its own
first, the same sweep runs and the outcome records the early exit.

RESULT. One line is written atomically to --result, then the process exits:
    stopped                              exit 0: gateway and every descendant are gone
    gateway_outlived_sigterm <n>         exit 1: n processes still in this tree
    owned_process_survived <n>           exit 1
    gateway_exited_early <stopped|owned_process_survived n>   exit 1
    unsupported <reason>                 exit 3: nothing was started
A trailing " interrupted" means a signal, not the control line, started the stop.
"""

import argparse
import ctypes
import os
import select
import signal
import subprocess
import sys
import time

PR_SET_CHILD_SUBREAPER = 36  # include/uapi/linux/prctl.h


def write_result(path, line):
    tmp = path + ".tmp"
    with open(tmp, "w") as handle:
        handle.write(line + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.rename(tmp, path)


def my_children():
    """Pids whose parent is this process, read from /proc/<pid>/stat.

    A pid seen here with this process as parent is this process's unreaped child, so its
    number cannot be reissued until this process reaps it. Missing a child in one scan is
    harmless: completion is decided by waitpid's ECHILD, never by this list.
    """
    me = os.getpid()
    found = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open("/proc/%s/stat" % name) as handle:
                stat = handle.read()
        except OSError:
            continue
        fields = stat[stat.rfind(")") + 2:].split()
        if len(fields) > 1 and fields[1] == str(me):
            found.append(int(name))
    return found


def remaining():
    return len(my_children())


def reap_all(signalled):
    """Reap every exited child. True once the kernel reports no children at all.

    A reaped pid is forgotten at once (its pidfd closed): the number may be reissued, and
    a later orphan that happens to carry it is a different process to be signalled anew.
    """
    while True:
        try:
            pid, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return True
        if pid == 0:
            return False
        pidfd = signalled.pop(pid, None)
        if pidfd is not None:
            os.close(pidfd)


def sweep(deadline, signalled):
    """SIGTERM each orphan once, through a pidfd, until no child is left or time is up."""
    while True:
        if reap_all(signalled):
            return "stopped"
        for pid in my_children():
            if pid in signalled:
                continue
            try:
                pidfd = os.pidfd_open(pid)
            except ProcessLookupError:
                continue
            signalled[pid] = pidfd
            try:
                signal.pidfd_send_signal(pidfd, signal.SIGTERM)
            except ProcessLookupError:
                pass
        if time.monotonic() >= deadline:
            return "owned_process_survived %d" % remaining()
        time.sleep(0.25)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--control", required=True)
    parser.add_argument("--result", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--term-wait", type=float, default=30.0)
    parser.add_argument("--sweep-wait", type=float, default=15.0)
    parser.add_argument("argv", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    argv = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
    if not argv:
        parser.error("gateway argv required after --")

    # Fail closed, before anything is started, where the mechanism is unavailable.
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        write_result(args.result, "unsupported pidfd")
        return 3
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        write_result(args.result, "unsupported subreaper errno=%d" % ctypes.get_errno())
        return 3

    # A signal to this process requests the one stop; it never ends this process early.
    requested = {"stop": False, "interrupted": False}

    def on_signal(_signum, _frame):
        requested["stop"] = True
        requested["interrupted"] = True

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, on_signal)

    # Opened read-write so the open neither blocks nor sees end-of-file while no writer
    # is attached (fifo(7) leaves this unspecified by POSIX; Linux defines it).
    control = os.open(args.control, os.O_RDWR | os.O_NONBLOCK)
    log = open(args.log, "ab")
    gateway = subprocess.Popen(
        argv, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT
    )
    # The gateway is this process's own unreaped child: its pid cannot be recycled yet.
    gateway_fd = os.pidfd_open(gateway.pid)

    buffered = b""
    early = False
    while not requested["stop"]:
        try:
            ready, _, _ = select.select([gateway_fd, control], [], [], 1.0)
        except InterruptedError:
            continue
        if gateway_fd in ready:
            early = True
            break
        if control in ready:
            try:
                buffered += os.read(control, 64)
            except BlockingIOError:
                pass
            if b"stop\n" in buffered:
                requested["stop"] = True

    signalled = {}
    if early:
        outcome = "gateway_exited_early " + sweep(time.monotonic() + args.sweep_wait, signalled)
        code = 1
    else:
        try:
            signal.pidfd_send_signal(gateway_fd, signal.SIGTERM)
        except ProcessLookupError:
            pass
        ready, _, _ = select.select([gateway_fd], [], [], args.term_wait)
        if gateway_fd not in ready:
            outcome = "gateway_outlived_sigterm %d" % remaining()
            code = 1
        else:
            outcome = sweep(time.monotonic() + args.sweep_wait, signalled)
            code = 0 if outcome == "stopped" else 1

    if requested["interrupted"]:
        outcome += " interrupted"
    write_result(args.result, outcome)
    return code


if __name__ == "__main__":
    sys.exit(main())
