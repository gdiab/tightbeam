#!/usr/bin/env python3
"""Record and alert when the local Tightbeam gateway is unavailable."""

from __future__ import annotations

import datetime
import http.client
import json
import os
import pathlib
import sys


HOST = "127.0.0.1"
PORT = 11373
PATH = "/version"
TIMEOUT_SECONDS = 5
DEFAULT_EVIDENCE_FILE = pathlib.Path(
    "/var/lib/tightbeam-gateway-down-probe/gateway-down.ndjson"
)


def check_gateway(host: str, port: int, timeout_seconds: float) -> None:
    connection = http.client.HTTPConnection(host, port, timeout=timeout_seconds)

    try:
        connection.request("GET", PATH)
        response = connection.getresponse()
        response.read()

        if response.status != 200:
            raise RuntimeError(f"GET {PATH} returned HTTP {response.status}")
    finally:
        connection.close()


def record_down_event(
    evidence_file: pathlib.Path, host: str, port: int, error: BaseException
) -> None:
    event = {
        "at": datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z"),
        "event": "gateway-down",
        "endpoint": f"http://{host}:{port}{PATH}",
        "error": f"{type(error).__name__}: {error}",
    }

    evidence_file.parent.mkdir(parents=True, exist_ok=True)

    with evidence_file.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, separators=(",", ":"), sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def run(
    *,
    host: str = HOST,
    port: int = PORT,
    timeout_seconds: float = TIMEOUT_SECONDS,
    evidence_file: pathlib.Path = DEFAULT_EVIDENCE_FILE,
) -> int:
    try:
        check_gateway(host, port, timeout_seconds)
    except Exception as error:
        try:
            record_down_event(evidence_file, host, port, error)
        except Exception as record_error:
            print(
                f"ALERT tightbeam gateway down at {host}:{port}; "
                f"could not record {evidence_file}: {record_error}",
                file=sys.stderr,
            )
            return 2

        print(
            f"ALERT tightbeam gateway down at {host}:{port}; "
            f"recorded {evidence_file}",
            file=sys.stderr,
        )
        return 1

    print(f"HEALTHY tightbeam gateway at {host}:{port}")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
