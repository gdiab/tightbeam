#!/usr/bin/env python3
"""Stage 1 P5c-H checks (stage1-v12 P5c-H, F1 erratum 1 rev 4 §1c.2).

Run only by .github/workflows/root-admin-evidence.yml, outside every suite. It reads
files and the throwaway base's state.db and launches nothing; the workflow does every
account and sudo step itself. Pairing codes and recovery secrets are never printed:
terminal captures are redacted before anything is logged.

  snapshot <base>                         one line per file: path and sha256
  real-root <base> <runner> <uid> <gid> <code capture> <secret capture>
                                          A6, A7, A8 and A11 after the real-root runs
  alerts <base> <runner>                  A9 after the boot observation
"""

import hashlib
import json
import os
import re
import sqlite3
import sys

CODE = re.compile(r"TB-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}")
SECRET = re.compile(r"TBR-[0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5}-[0-9A-Z]{5}")


def fail(message):
    print(f"FAIL: {message}")
    sys.exit(1)


def redact(text):
    return SECRET.sub("TBR-<redacted>", CODE.sub("TB-<redacted>", text))


def read_capture(path):
    with open(path, "rb") as handle:
        return handle.read().decode("utf-8", errors="replace")


def snapshot(base):
    for directory, _subdirs, files in sorted(os.walk(base)):
        for name in sorted(files):
            path = os.path.join(directory, name)
            with open(path, "rb") as handle:
                digest = hashlib.sha256(handle.read()).hexdigest()
            print(f"{os.path.relpath(path, base)} {digest}")


def connect(base):
    return sqlite3.connect(os.path.join(base, "state.db"))


def every_row_text(db):
    for (table,) in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'"):
        for row in db.execute(f'SELECT * FROM "{table}"'):
            yield table, repr(row)


def real_root(base, runner, uid, gid, code_capture, secret_capture):
    code_text = read_capture(code_capture)
    secret_text = read_capture(secret_capture)
    codes = CODE.findall(code_text)
    secrets = SECRET.findall(secret_text)
    if len(codes) != 1:
        fail(f"A6: expected the code once on the pairing-code terminal, found {len(codes)}")
    if len(secrets) != 1:
        fail(f"A6: expected the secret once on the recovery-enroll terminal, found {len(secrets)}")
    code, secret = codes[0], secrets[0]

    # A8: still the database owner's, uid and gid, after the real root runs.
    owned = [os.path.join(base, name) for name in sorted(os.listdir(base))
             if name.startswith("state.db") or name == "gateway.lock"]
    if not any(path.endswith("gateway.lock") for path in owned):
        fail("A8: no gateway.lock in the base")
    for path in owned:
        stat = os.stat(path)
        if (stat.st_uid, stat.st_gid) != (int(uid), int(gid)):
            fail(f"A8: {os.path.basename(path)} is {stat.st_uid}:{stat.st_gid}, not the owner {uid}:{gid}")
        print(f"A8 ok: {os.path.basename(path)} owned by {stat.st_uid}:{stat.st_gid}")

    db = connect(base)
    actions = [json.loads(detail) for (detail,) in db.execute(
        "SELECT detail FROM lifecycle_events WHERE kind = 'root_admin_action' ORDER BY id")]
    if [action.get("action") for action in actions] != ["pairing-code", "recovery-enroll"]:
        fail(f"A7: root_admin_action order {[action.get('action') for action in actions]}")
    for action in actions:
        if action.get("userId") != "george":
            fail(f"A7: userId {action.get('userId')!r}")
        if action.get("account") != runner:
            fail(f"A7: account {action.get('account')!r} is not the invoking runner account {runner!r}")
        if not str(action.get("tty", "")).startswith("/dev/"):
            fail(f"A7: tty {action.get('tty')!r} is not a real terminal")
        if not isinstance(action.get("at"), int):
            fail("A7: no integer time")
        print(f"A7 ok: {action['action']} by {action['account']} on {action['tty']}")
    code_id = actions[0].get("codeId", "")
    if not code_id.startswith("pc_"):
        fail(f"A7: code id {code_id!r}")

    # A6: only verifiers are stored.
    rows = db.execute("SELECT length(verifier), length(salt) FROM pairing_codes WHERE codeId = ?",
                      (code_id,)).fetchall()
    if rows != [(32, 16)]:
        fail(f"A6: pairing code verifier rows {rows}")
    rows = db.execute("SELECT length(verifier), length(salt) FROM recovery_secrets WHERE userId = 'george'").fetchall()
    if rows != [(32, 16)]:
        fail(f"A6: recovery secret verifier rows {rows}")
    print("A6 ok: one 32-byte verifier and a 16-byte salt for the code and for the secret")

    # A11: neither value appears in any record.
    for table, text in every_row_text(db):
        if code in text or secret in text:
            fail(f"A11: a code or secret appears in table {table}")
    print("A11 ok: no code or secret in any table")

    print("--- pairing-code terminal (redacted) ---")
    print(redact(code_text))
    print("--- recovery-enroll terminal (redacted) ---")
    print(redact(secret_text))


def alerts(base, runner):
    db = connect(base)
    rows = db.execute(
        "SELECT kind, body FROM owner_alerts WHERE kind IN ('root-pairing-code', 'root-recovery-enroll') ORDER BY kind"
    ).fetchall()
    if [kind for kind, _body in rows] != ["root-pairing-code", "root-recovery-enroll"]:
        fail(f"A9: owner alerts {[kind for kind, _body in rows]}")
    wording = {"root-pairing-code": "issued a pairing code for george",
               "root-recovery-enroll": "enrolled a recovery secret for george"}
    for kind, body in rows:
        if wording[kind] not in body or f"by {runner} on /dev/" not in body:
            fail(f"A9: the {kind} alert does not name the action, user, account and terminal")
        print(f"A9 ok: one {kind} alert naming george, {runner} and the terminal")

    admins = [user for (user,) in db.execute(
        "SELECT userId FROM users WHERE isAdmin = 1 AND removedAt IS NULL")]
    wakes = db.execute("SELECT sessionKey, prompt FROM wakes WHERE class = 'blocker'").fetchall()
    if len(wakes) != 2 * len(admins):
        fail(f"A9: {len(wakes)} blocker wakes for {len(admins)} admins and 2 actions")
    for action in wording.values():
        if sum(1 for _session, prompt in wakes if action in prompt) != len(admins):
            fail(f"A9: not one '{action}' wake per admin")
    print(f"A9 ok: {len(wakes)} blocker wakes, one per action for each of {len(admins)} admins")


def main(argv):
    if len(argv) == 3 and argv[1] == "snapshot":
        snapshot(argv[2])
    elif len(argv) == 8 and argv[1] == "real-root":
        real_root(*argv[2:])
    elif len(argv) == 4 and argv[1] == "alerts":
        alerts(argv[2], argv[3])
    else:
        print(__doc__)
        sys.exit(64)


if __name__ == "__main__":
    main(sys.argv)
