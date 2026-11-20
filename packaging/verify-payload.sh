#!/bin/sh
set -eu
ARTIFACT=${1:?usage: verify-payload.sh artifact.tgz}
TEMP_DIR=$(mktemp -d)
TEMP_DIR=$(cd "$TEMP_DIR" && pwd -P)
trap 'rm -rf "$TEMP_DIR"' EXIT HUP INT TERM
python3 "$(dirname "$0")/extract-payload.py" "$ARTIFACT" "$TEMP_DIR"
# Core fix (A), C21.1 (ii)-(iii): no package carries an Erlang cookie.
COOKIES=$(find "$TEMP_DIR/tightbeam" \( -path '*/releases/COOKIE' -o -name '.erlang.cookie' \) -print)
if [ -n "$COOKIES" ]; then
  echo "payload refused: the package carries an Erlang cookie (C21.1): $COOKIES" >&2
  exit 1
fi
elixir "$(dirname "$0")/payload-manifest.exs" verify "$TEMP_DIR/tightbeam"
