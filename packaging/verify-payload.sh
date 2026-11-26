#!/bin/sh
set -eu
ARTIFACT=${1:?usage: verify-payload.sh artifact.tgz}
TEMP_DIR=$(mktemp -d)
TEMP_DIR=$(cd "$TEMP_DIR" && pwd -P)
trap 'rm -rf "$TEMP_DIR"' EXIT HUP INT TERM
python3 "$(dirname "$0")/extract-payload.py" "$ARTIFACT" "$TEMP_DIR"
# Stage 1 (stage1-v12 §6.3): no package carries a CLI built with the root-admin test
# seam (cargo feature root-admin-seam); such a build carries this marker.
if grep -r -l -a -F "tightbeam-root-admin-test-seam" "$TEMP_DIR/tightbeam" >/dev/null 2>&1; then
  echo "payload refused: the package carries a root-admin test-seam build of the CLI" >&2
  exit 1
fi
elixir "$(dirname "$0")/payload-manifest.exs" verify "$TEMP_DIR/tightbeam"
