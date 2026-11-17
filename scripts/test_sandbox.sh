#!/bin/sh
# Run a local test command inside a sandbox that exists before the VM or cargo
# starts, so no test can resolve a live Tightbeam gateway or a real credential
# (F1, wi_34a7be66). Every local suite runs through here:
#
#   scripts/test_sandbox.sh mix test [args]
#   scripts/test_sandbox.sh cargo test --manifest-path cli/Cargo.toml [args]
#
# The CLI finds its gateway from an ancestor .tightbeam-session first, then
# TIGHTBEAM_URL/TOKEN, then <base>/gateway.json under the real HOME. A test that
# inherits any of those reaches a live gateway with a real credential. So the
# command runs with an empty HOME and XDG dirs, a toolbox PATH of named real
# tools (no tightbeam other than this repository's build, no harness or
# credential tools), and `env -i` with an allowlist. The suite's own preflight
# (test/test_helper.exs, cli test_isolation) refuses to run without this marker.
set -eu

refuse() {
  printf 'tightbeam-test-sandbox: refused: %s\n' "$1" >&2
  exit 78
}

[ "$#" -ge 1 ] || refuse "usage: scripts/test_sandbox.sh <command> [args...]"

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repo=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
cwd=$(pwd -P)

session_ancestor() {
  dir=$1
  while :; do
    if [ -e "$dir/.tightbeam-session" ]; then
      printf '%s\n' "$dir/.tightbeam-session"
      return 0
    fi
    [ "$dir" = / ] && return 1
    dir=$(dirname -- "$dir")
  done
}

for start in "$repo" "$cwd"; do
  if found=$(session_ancestor "$start"); then
    refuse "$start is inside a Tightbeam session tree ($found); run tests from a checkout outside any session tree, or on hosted CI"
  fi
done

case "$cwd" in
  "$repo" | "$repo"/*) : ;;
  *) refuse "run from inside the repository ($repo), not $cwd" ;;
esac

# A test may itself run this launcher (scripts/verify_mix.sh under test). That
# nested run gets its own sandbox but must not touch the outer run's <repo>/tmp.
nested=""
outer=${TIGHTBEAM_TEST_SANDBOX:-}
if [ -n "$outer" ] && [ -f "$outer/.tightbeam-test-sandbox" ]; then
  nested=1
fi

# ExUnit's tmp_dir is <repo>/tmp. It must resolve inside the sandbox, so a test's
# tmp dir is under the sandbox root like every other place a child may run.
if [ -z "$nested" ]; then
  if [ -L "$repo/tmp" ]; then
    rm -f -- "$repo/tmp"
  elif [ -e "$repo/tmp" ]; then
    refuse "$repo/tmp is a real directory from an unsandboxed run; remove it and retry"
  fi
fi

root=$(mktemp -d /tmp/tightbeam-test-sandbox.XXXXXXXX)
root=$(CDPATH= cd -- "$root" && pwd -P)
cleanup() {
  if [ -z "$nested" ] && [ -L "$repo/tmp" ]; then
    rm -f -- "$repo/tmp"
  fi
  rm -rf -- "$root"
}
trap cleanup EXIT HUP INT TERM

if found=$(session_ancestor "$root"); then
  refuse "sandbox root $root is inside a Tightbeam session tree ($found)"
fi

: >"$root/.tightbeam-test-sandbox"
mkdir -p "$root/home" "$root/xdg/config" "$root/xdg/data" "$root/xdg/state" \
  "$root/xdg/cache" "$root/bin" "$root/tmp" "$root/exunit-tmp" "$root/mix" \
  "$root/hex" "$root/cargo"
[ -n "$nested" ] || ln -s "$root/exunit-tmp" "$repo/tmp"

# Toolbox: each entry is a real install, never a mise or rustup shim (a shim
# needs the real HOME to dispatch). Resolution happens here, before the swap.
real_home=${HOME:-}
caller_path=${PATH:-}
resolve() {
  name=$1
  path=""
  # Rust: ~/.cargo/bin/cargo is a rustup proxy that needs the real HOME, so ask
  # rustup for the real toolchain binary first.
  case "$name" in
    cargo | rustc | rustdoc)
      if command -v rustup >/dev/null 2>&1; then
        path=$(rustup which "$name" 2>/dev/null || :)
      fi
      ;;
  esac
  # Otherwise the first real file on the caller's PATH (what CI's setup-beam and
  # a developer's pinned PATH select), skipping shim and Tightbeam directories.
  if [ -z "$path" ]; then
    saved_ifs=$IFS
    IFS=:
    for dir in $caller_path; do
      case "$dir" in
        '' | */shims | */shims/* | "$real_home"/.tightbeam/* | "$real_home"/.local/bin) continue ;;
      esac
      if [ -f "$dir/$name" ] && [ -x "$dir/$name" ]; then
        path="$dir/$name"
        break
      fi
    done
    IFS=$saved_ifs
  fi
  # Only shims on PATH: ask mise for the real install.
  if [ -z "$path" ] && command -v mise >/dev/null 2>&1; then
    path=$(mise which "$name" 2>/dev/null || :)
  fi
  case "$path" in
    */shims/* | "$real_home"/.tightbeam/* | "$real_home"/.local/bin/*) path="" ;;
  esac
  case "$path" in
    /*) printf '%s' "$path" ;;
  esac
}

link_tool() {
  path=$(resolve "$1")
  if [ -n "$path" ]; then
    case "$1" in
      # OTP's and Elixir's launch scripts find their install from their own
      # path ($0) without following symlinks (setup-beam's macOS erl falls back
      # to its build prefix), so these get an exec wrapper, not a symlink.
      erl | erlc | escript | elixir | elixirc | iex | mix)
        printf '#!/bin/sh\nexec "%s" "$@"\n' "$path" >"$root/bin/$1"
        chmod 755 "$root/bin/$1"
        ;;
      *) ln -s "$path" "$root/bin/$1" ;;
    esac
  elif [ "${2:-}" = required ]; then
    refuse "required tool $1 was not found on PATH"
  fi
}

for tool in sh env erl elixir mix git; do
  link_tool "$tool" required
done

# Everything else the suite, its fixtures, the toolchain's own wrapper scripts
# (erl/elixir/mix call dirname, basename, readlink, sed, uname) and the build
# use. Absent tools are simply not linked; a test that needs one fails closed.
for tool in bash erlc escript elixirc iex node python3 sqlite3 cargo rustc rustdoc \
  cc c++ gcc clang ld ar as make pkg-config \
  cat cp mv rm mkdir rmdir ln ls chmod chown touch stat readlink realpath dirname \
  basename sed awk grep egrep fgrep tr cut head tail sort uniq wc tee xargs find \
  printf echo test expr seq true false sleep kill ps pgrep pkill id uname date \
  tar gzip gunzip zcat mktemp mkfifo cmp diff od nohup timeout setsid flock \
  which hostname whoami sha256sum shasum md5sum file mount df du tty stty \
  getconf locale perl install patch curl jq rsync base64 unzip zip xxd nproc lsof getent \
  iconv paste comm rev tac shuf truncate sync column nl fold; do
  [ -e "$root/bin/$tool" ] || link_tool "$tool"
done

# Tightbeam CLIs: only this repository's builds. The fixture harness CLI is the
# registered test harness (config/test.exs).
ln -s "$repo/cli/target/release/tightbeam" "$root/bin/tightbeam"
[ -e "$repo/priv/harness_cli/fixture" ] &&
  ln -s "$repo/priv/harness_cli/fixture" "$root/bin/fixture"

for forbidden in gh ssh scp sftp op codex claude cursor-agent pi harklight-agent; do
  [ ! -e "$root/bin/$forbidden" ] || refuse "toolbox would expose $forbidden"
done

cat >"$root/gitconfig" <<'GITCONFIG'
[user]
	name = tightbeam-test
	email = test@tightbeam.invalid
[init]
	defaultBranch = main
GITCONFIG

# Mix needs its archives (hex) to load hex deps; copy them, never point at the
# real ~/.mix or ~/.hex (hex can hold an API key). Deps are fetched and compiled
# before the sandbox, so everything runs offline.
real_mix_home=${MIX_HOME:-$real_home/.mix}
if [ -d "$real_mix_home/archives" ]; then
  cp -R "$real_mix_home/archives" "$root/mix/archives"
fi

# Cargo: no credentials.toml (the crates.io token lives at the CARGO_HOME root);
# only the downloaded registry and git caches, used offline. Dependencies must
# be fetched before the sandbox (`cargo fetch --manifest-path cli/Cargo.toml`).
real_cargo_home=${CARGO_HOME:-$real_home/.cargo}
for cache in registry git; do
  [ -d "$real_cargo_home/$cache" ] && ln -s "$real_cargo_home/$cache" "$root/cargo/$cache"
done

# Smoke-run the toolchain under the sandbox environment; refuse if any fails.
smoke() {
  if ! output=$(env -i HOME="$root/home" PATH="$root/bin:$repo/cli/target/release" \
    LANG="${LANG:-C.UTF-8}" MIX_HOME="$root/mix" HEX_HOME="$root/hex" HEX_OFFLINE=1 \
    CARGO_HOME="$root/cargo" CARGO_NET_OFFLINE=true TMPDIR="$root/tmp" \
    "$@" 2>&1); then
    printf '%s\n' "$output" | tail -20 >&2
    refuse "toolchain smoke failed in the sandbox: $* (output above)"
  fi
}
smoke elixir --version
smoke mix --version
smoke git --version
if [ -e "$root/bin/cargo" ]; then
  smoke cargo --version
fi

# Named, credential-free variables inherited only when the caller set them: the
# locale, the authoritative-gate claim (scripts/verify_mix.sh) and the macOS CI
# diagnostic (test/test_helper.exs). They go before the command, after env -i.
for name in LC_ALL LC_CTYPE TERM TIGHTBEAM_AUTHORITATIVE_GATE TIGHTBEAM_GATE_NODE \
  TIGHTBEAM_PORT DD36_DARWIN_DIAGNOSTIC_DIR RUNNER_TEMP CANDIDATE_SHA; do
  eval "set_flag=\${$name+set}"
  if [ "$set_flag" = set ]; then
    eval "value=\${$name}"
    set -- "$name=$value" "$@"
  fi
done

# The command runs as a child so the EXIT/signal trap removes the sandbox and the
# <repo>/tmp link afterwards, whatever the outcome.
status=0
env -i \
  HOME="$root/home" \
  XDG_CONFIG_HOME="$root/xdg/config" \
  XDG_DATA_HOME="$root/xdg/data" \
  XDG_STATE_HOME="$root/xdg/state" \
  XDG_CACHE_HOME="$root/xdg/cache" \
  PATH="$root/bin:$repo/cli/target/release" \
  TMPDIR="$root/tmp" \
  LANG="${LANG:-C.UTF-8}" \
  MIX_ENV="${MIX_ENV:-test}" \
  MIX_HOME="$root/mix" \
  HEX_HOME="$root/hex" \
  HEX_OFFLINE=1 \
  GIT_CONFIG_GLOBAL="$root/gitconfig" \
  GIT_CONFIG_NOSYSTEM=1 \
  CARGO_HOME="$root/cargo" \
  CARGO_NET_OFFLINE=true \
  CARGO_TARGET_DIR="$repo/cli/target" \
  TIGHTBEAM_TEST_SANDBOX="$root" \
  "$@" || status=$?
exit "$status"
