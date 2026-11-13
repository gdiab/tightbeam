#!/usr/bin/env python3
"""Own one gateway process tree for the hosted live smoke, and stop all of it exactly once.

    python3 scripts/hosted_smoke_supervisor.py --dir DIR --log FILE \
        [--term-wait SECONDS] [--sweep-wait SECONDS] -- GATEWAY_ARGV...

DIR must exist and hold the control FIFO DIR/control. The supervisor writes, each atomically:
    DIR/owned     once it holds the gateway's pidfd (the control handoff);
    DIR/received  the number of "stop" lines it has READ from the FIFO: written when the
                  first arrives and rewritten with the final total, after draining the
                  FIFO, just before the result. This is the receiver's own count, the
                  authoritative record of delivery;
    DIR/stopping  the moment its one stop begins, whatever started it;
    DIR/result    one line, as its last act.

OWNERSHIP. This process marks itself a child subreaper (prctl(2) PR_SET_CHILD_SUBREAPER)
before anything is started. Every process the gateway ever creates therefore stays inside
this process's tree: an orphan is reparented to its nearest living subreaper ancestor,
which is this process (or a subreaper below it), never to init. Leaving the process group
or the session (setsid, double fork) does not leave the tree. So when waitpid(-1) reports
ECHILD, the kernel is stating that no descendant is left.

CONTROL BEFORE LAUNCH. The gateway is forked as a child that waits on a pipe before it
execs. The supervisor opens the child's pidfd first. Only if that succeeds does it record
DIR/owned and release the child. If it fails, the child is released with nothing to run,
exits, and is reaped; the gateway never starts uncontrolled. The child is this process's
own unreaped child throughout, so its pid cannot be recycled (pidfd_open(2), NOTES).

IDENTITY. Nothing is signalled by number. The gateway and every orphan that reaches this
process are signalled through a pidfd, which refers to one process for its whole life
(pidfd_send_signal(2)). An orphan is found as this process's own child in /proc and its
pidfd is opened before anything is reaped, so its pid cannot have been reissued either.
Descendants still under a living parent are not signalled directly; they reach this
process, and are signalled, once their parent has exited.

ONE ATTEMPT. A stop is requested by the line "stop" on the control FIFO, or by SIGTERM,
SIGINT or SIGHUP to this process. It runs once:
  1. send SIGTERM to the gateway and wait --term-wait seconds for it to exit;
  2. sweep: SIGTERM each orphan once as it arrives, reap what exits, until ECHILD or
     --sweep-wait seconds.
There is no SIGKILL, no second signal and no second stop. If the gateway exits on its own
first, the same sweep runs and the outcome records the early exit. A pidfd operation that
fails for any reason other than "already gone" is recorded and that process is not
retried; it then counts against completion.

RESULT, the last act, written atomically; then the process exits:
    stopped                                  exit 0: gateway and every descendant gone
    gateway_outlived_sigterm direct_children=N            exit 1
    owned_process_survived direct_children=N              exit 1
    gateway_exited_early <stopped|owned_process_survived ...>   exit 1
    control_unavailable <reason>             exit 3: the gateway was never started
    supervisor_error <exception>             exit 1: ownership lost; tree left running
Suffixes: " control_error=<ERRNO,...>" when a pidfd operation failed, and " interrupted"
when a signal, not the control line, started the stop. N counts this process's direct
children still present: a LOWER bound on live descendants, never proof of absence.
"""

import argparse
import ctypes
import errno
import os
import select
import signal
import sys
import time

PR_SET_CHILD_SUBREAPER = 36  # include/uapi/linux/prctl.h


def write_atomic(path, line):
    tmp = path + ".tmp"
    with open(tmp, "w") as handle:
        handle.write(line + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.rename(tmp, path)


class Control:
    """The control FIFO, read by this process only. Counts every "stop" line received."""

    def __init__(self, directory):
        self.directory = directory
        self.fd = os.open(
            os.path.join(directory, "control"), os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC
        )
        self.buffered = b""
        self.received = 0

    def read(self):
        """Read what is waiting; return True if at least one new stop line arrived."""
        before = self.received
        while True:
            try:
                chunk = os.read(self.fd, 4096)
            except BlockingIOError:
                break
            if not chunk:
                break
            self.buffered += chunk
        *lines, self.buffered = self.buffered.split(b"\n")
        self.received += sum(1 for line in lines if line == b"stop")
        if self.received != before:
            write_atomic(os.path.join(self.directory, "received"), str(self.received))
        return self.received > before

    def final(self):
        """Drain what is still queued and record the final count, even if it is zero."""
        self.read()
        write_atomic(os.path.join(self.directory, "received"), str(self.received))


def errname(error):
    return errno.errorcode.get(error.errno, str(error.errno))


def direct_children():
    """Pids whose parent is this process, read from /proc/<pid>/stat.

    A pid seen here with this process as parent is this process's unreaped child, so its
    number cannot be reissued until this process reaps it. Missing a child in one scan is
    harmless: completion is decided by waitpid's ECHILD, never by this list.
    """
    me = str(os.getpid())
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
        if len(fields) > 1 and fields[1] == me:
            found.append(int(name))
    return found


class Owner:
    def __init__(self):
        self.handles = {}  # pid -> pidfd, for processes already signalled
        self.unreachable = set()  # pids whose pidfd operation failed; never retried
        self.errors = []

    def record(self, error):
        name = errname(error)
        if name not in self.errors:
            self.errors.append(name)

    def signal_once(self, pidfd):
        try:
            signal.pidfd_send_signal(pidfd, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError as error:
            self.record(error)

    def reap_all(self):
        """Reap every exited child. True once the kernel reports no children at all.

        A reaped pid is forgotten at once (its pidfd closed): the number may be reissued,
        and a later orphan carrying it is a different process.
        """
        while True:
            try:
                pid, _status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                return True
            if pid == 0:
                return False
            pidfd = self.handles.pop(pid, None)
            if pidfd is not None:
                os.close(pidfd)
            self.unreachable.discard(pid)

    def sweep(self, deadline):
        while True:
            if self.reap_all():
                return "stopped"
            for pid in direct_children():
                if pid in self.handles or pid in self.unreachable:
                    continue
                try:
                    pidfd = os.pidfd_open(pid)
                except ProcessLookupError:
                    continue
                except OSError as error:
                    self.record(error)
                    self.unreachable.add(pid)
                    continue
                self.handles[pid] = pidfd
                self.signal_once(pidfd)
            if time.monotonic() >= deadline:
                return "owned_process_survived direct_children=%d" % len(direct_children())
            time.sleep(0.25)


def launch(argv, log_fd):
    """Fork the gateway held at a pipe; return (pid, pidfd, gate) or raise after cleanup."""
    devnull = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
    gate_r, gate_w = os.pipe()  # both non-inheritable, so nothing leaks past exec
    pid = os.fork()
    if pid == 0:
        try:
            os.close(gate_w)
            if os.read(gate_r, 2) == b"go":
                os.dup2(devnull, 0)
                os.dup2(log_fd, 1)
                os.dup2(log_fd, 2)
                os.execvp(argv[0], argv)
        finally:
            os._exit(127)
    os.close(gate_r)
    os.close(devnull)
    try:
        pidfd = os.pidfd_open(pid)
    except OSError:
        os.close(gate_w)  # the child reads end-of-file and exits without running anything
        os.waitpid(pid, 0)
        raise
    return pid, pidfd, gate_w


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--term-wait", type=float, default=30.0)
    parser.add_argument("--sweep-wait", type=float, default=15.0)
    parser.add_argument("argv", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    argv = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
    if not argv:
        parser.error("gateway argv required after --")
    result_path = os.path.join(args.dir, "result")

    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        write_atomic(result_path, "control_unavailable pidfd_api_missing")
        return 3
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        write_atomic(result_path, "control_unavailable subreaper errno=%d" % ctypes.get_errno())
        return 3

    # A signal to this process requests the one stop; it never ends this process early.
    requested = {"stop": False, "interrupted": False}

    def on_signal(_signum, _frame):
        requested["stop"] = True
        requested["interrupted"] = True

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, on_signal)

    # Opened read-write so the open neither blocks nor sees end-of-file while no writer
    # is attached (Linux fifo(7) behavior).
    control = Control(args.dir)
    log_fd = os.open(args.log, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC, 0o600)

    try:
        gateway_pid, gateway_fd, gate_w = launch(argv, log_fd)
    except OSError as error:
        write_atomic(result_path, "control_unavailable pidfd_open=%s" % errname(error))
        return 3

    owner = Owner()
    try:
        write_atomic(os.path.join(args.dir, "owned"), "owned")
        os.write(gate_w, b"go")
        os.close(gate_w)

        early = False
        while not requested["stop"]:
            ready, _, _ = select.select([gateway_fd, control.fd], [], [], 1.0)
            if gateway_fd in ready:
                early = True
                break
            if control.fd in ready and control.read():
                requested["stop"] = True

        write_atomic(os.path.join(args.dir, "stopping"), "early" if early else "requested")
        if early:
            outcome = "gateway_exited_early " + owner.sweep(time.monotonic() + args.sweep_wait)
            code = 1
        else:
            owner.handles[gateway_pid] = gateway_fd
            owner.signal_once(gateway_fd)
            ready, _, _ = select.select([gateway_fd], [], [], args.term_wait)
            if gateway_fd not in ready:
                outcome = "gateway_outlived_sigterm direct_children=%d" % len(direct_children())
                code = 1
            else:
                outcome = owner.sweep(time.monotonic() + args.sweep_wait)
                code = 0 if outcome == "stopped" and not owner.errors else 1
        control.final()
    except BaseException as error:  # ownership is lost: say so, never claim a stop
        try:
            control.final()
        except BaseException:
            pass
        write_atomic(result_path, "supervisor_error %s" % type(error).__name__)
        return 1

    if owner.errors:
        outcome += " control_error=" + ",".join(owner.errors)
    if requested["interrupted"]:
        outcome += " interrupted"
    write_atomic(result_path, outcome)
    return code


if __name__ == "__main__":
    sys.exit(main())
