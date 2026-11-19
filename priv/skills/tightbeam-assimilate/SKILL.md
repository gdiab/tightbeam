---
name: tightbeam-assimilate
description: Prepare George to onboard a machine as a tightbeam host — read-only preconditions, the exact assimilate command he runs, the register-host command he sends from Clawline, placement and verification. Use when the operator asks to assimilate a machine.
---

Assimilation onboards a machine as a host. George runs it; you prepare it. Never run
`tightbeam assimilate`, not even with `--dry-run`, and never run or ask another agent to
run `register-host`, `approve-device`, `deny-device`, `revoke-device`, `add-user`,
`promote-user` or `remove-user`. The gateway accepts those only from George's
admin-paired device. Your part is to check what you can read, prepare the exact command,
and give it to George, saying the step is his.

1. Preconditions. Over non-interactive ssh (`ssh -o BatchMode=yes <ssh-dest> …`),
   confirm key-based access and that node, npm, rsync and the CLI of every harness to
   enable (`claude`, `codex`) are on the PATH that such a session sees. A binary
   reachable only through a login profile does not count. Installing them is George's,
   never assimilation's. Report what is missing.
2. The ceremony. Give George this command to run in his own terminal on the gateway
   host:

       tightbeam assimilate <ssh-dest> --as-user <his user id> --harness <h>[,<h>] [--name <hostname>] [--base-dir <path>]

   `<ssh-dest>` is anything ssh resolves (tailnet names work); `--name` defaults from
   the destination. It probes the target, creates the base dir, and installs the ACP
   adapters and this CLI.
3. Registration. The REGISTER step is refused for that terminal, as for every caller
   other than George's paired device. It prints
   `[assimilate] REGISTER... registration pending George` and the exact
   `/tightbeam register-host <name> <ssh-dest> <base-dir> --cli-bin … --adapter-bin-dir …`
   line, then exits non-zero with `registration pending George`. That is the expected
   stop, not a failure. George sends that line unchanged from Clawline; the host exists
   only after he does. If you relay the line, copy it exactly as printed.
4. Different architectures. If the CLI step warns that the satellite's target differs
   from this binary's, build on the satellite: copy the repo's `cli/` source over
   (rsync), run `cargo build --release` there (it needs a Rust toolchain), install the
   result at `<base-dir>/bin/tightbeam`, and have George re-run the ceremony. Every
   other step is idempotent.
5. Credentials. Credentials never travel between machines. Each harness on the new host
   is onboarded there with `tightbeam onboard`, which needs an interactive login: give
   George the command and say the step is his. Until then, turns placed there fail with
   an auth marker.
6. Placement. A registered host is used only where an archetype's `where` admits it.
   Add the host through the identity seam with `tightbeam identity edit <archetype>
   --manifest`. It applies when the edit publishes; no restart is needed. Editing
   `where` changes no guidance, so it costs no session its memory.
7. Verify. The host appears in `tightbeam list`, and `spawn --host <name>` places a
   session there.
