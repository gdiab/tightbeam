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

# The caller's TMPDIR (macOS: /var/folders/..., where a new directory keeps its
# setgid bit) or /tmp; either way the ancestry check below must pass.
root=$(mktemp -d "${TMPDIR:-/tmp}/tightbeam-test-sandbox.XXXXXXXX")
root=$(CDPATH= cd -- "$root" && pwd -P)
cleanup() {
  # Seeded Mix archives are read-only; make them removable first.
  chmod -R u+w -- "$root" 2>/dev/null || :
  rm -rf -- "$root"
}
trap cleanup EXIT HUP INT TERM

if found=$(session_ancestor "$root"); then
  refuse "sandbox root $root is inside a Tightbeam session tree ($found)"
fi

: >"$root/.tightbeam-test-sandbox"
mkdir -p "$root/home" "$root/xdg/config" "$root/xdg/data" "$root/xdg/state" \
  "$root/xdg/cache" "$root/bin" "$root/tmp" "$root/home/.mix" "$root/hex" "$root/cargo"

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
      # OTP's and Elixir's shell launchers find their install from their own
      # path ($0) without following symlinks (setup-beam's macOS erl falls back
      # to its build prefix), so these get an exec wrapper, not a symlink. mix
      # stays a symlink: `elixir -S mix` evaluates the file found on PATH as
      # Elixir source.
      erl | erlc | escript | elixir | elixirc | iex)
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
  iconv paste comm rev tac shuf truncate sync column nl fold xcrun sandbox-exec; do
  [ -e "$root/bin/$tool" ] || link_tool "$tool"
done

# macOS: Apple's sqlite3 can refuse a closed Exqlite WAL database, so the
# portable-schema fixture (test/support/guard_toplines_portable_runtime.exs)
# runs Homebrew's standard sqlite3 by its keg path, in this order. Linking it
# makes that path a toolbox tool's target, as the isolation helper requires of
# any executable named by path.
for keg in /opt/homebrew/opt/sqlite/bin/sqlite3 /usr/local/opt/sqlite/bin/sqlite3; do
  if [ -x "$keg" ]; then
    ln -s "$keg" "$root/bin/sqlite3-standard"
    break
  fi
done

# Tightbeam CLIs: only this repository's builds. The fixture harness CLI is the
# registered test harness (config/test.exs).
ln -s "$repo/cli/target/release/tightbeam" "$root/bin/tightbeam"
[ -e "$repo/priv/harness_cli/fixture" ] &&
  ln -s "$repo/priv/harness_cli/fixture" "$root/bin/fixture"

for forbidden in gh ssh scp sftp op codex claude cursor-agent pi harklight-agent \
  sudo su doas pkexec; do
  [ ! -e "$root/bin/$forbidden" ] || refuse "toolbox would expose $forbidden"
done

# The product resolves an ssh executable when it prepares remote harness launch
# vectors, so something named ssh must resolve. This one is a tripwire: it
# never connects anywhere and can read no key (the HOME is empty).
cat >"$root/bin/ssh" <<'TRIPWIRE'
#!/bin/sh
# tightbeam-test-sandbox ssh tripwire (wi_34a7be66)
echo "ssh: tripwire in the Tightbeam test sandbox; no remote access" >&2
exit 255
TRIPWIRE
chmod 755 "$root/bin/ssh"

cat >"$root/gitconfig" <<'GITCONFIG'
[user]
	name = tightbeam-test
	email = test@tightbeam.invalid
[init]
	defaultBranch = main
GITCONFIG

# F1 erratum 2 C15: seed the sandbox home with read-only regular-file copies of
# exactly the build material the suite's setup (config/test.exs) needs, and
# nothing else from the real home: the Hex archive, the versioned rebar3 and the
# elixir_make cache. Never ~/.hex (it can hold an API key), other Mix
# configuration, provider or harness homes, or any credential file.
copy_regular() {
  # copy_regular <source> <target>: copy, refuse anything in the copy that is not
  # a regular file or a directory (a symlink, fifo, socket or device), then make
  # the whole copy read-only for the run.
  mkdir -p "$(dirname -- "$2")"
  cp -R -- "$1" "$2"
  if [ -n "$(find "$2" ! -type d ! -type f -print -quit)" ]; then
    refuse "seeded build material $1 contains something other than regular files and directories"
  fi
  chmod -R a-w -- "$2"
}
real_mix_home=${MIX_HOME:-$real_home/.mix}
for archive in "$real_mix_home"/archives/hex-*; do
  [ -e "$archive" ] || continue
  copy_regular "$archive" "$root/home/.mix/archives/$(basename -- "$archive")"
done
for rebar in "$real_mix_home"/elixir/*/rebar3; do
  [ -f "$rebar" ] || continue
  [ -L "$rebar" ] && refuse "rebar3 at $rebar is a symlink"
  version_dir=$(basename -- "$(dirname -- "$rebar")")
  copy_regular "$rebar" "$root/home/.mix/elixir/$version_dir/rebar3"
done
if [ -d "$real_home/.cache/elixir_make" ]; then
  copy_regular "$real_home/.cache/elixir_make" "$root/home/.cache/elixir_make"
fi

# One Cargo home per run, shared by the Mix suite and cargo test (C15): read-only
# regular-file copies of the registry and git caches, used offline. It holds no
# credentials.toml, credentials or config.toml. Only the Cargo home's own root
# stays writable, for Cargo's lock and bookkeeping files; nothing seeded is
# writable. Every crate the run builds (the CLI and each native extension) must
# already be unpacked in the caches: offline, a missing crate refuses and
# nothing is fetched.
real_cargo_home=${CARGO_HOME:-$real_home/.cargo}
for cache in registry git; do
  [ -d "$real_cargo_home/$cache" ] && copy_regular "$real_cargo_home/$cache" "$root/cargo/$cache"
done

# Smoke-run the toolchain under the sandbox environment; refuse if any fails.
smoke() {
  if ! output=$(env -i HOME="$root/home" PATH="$root/bin:$repo/cli/target/release" \
    LANG="${LANG:-C.UTF-8}" MIX_HOME="$root/home/.mix" HEX_HOME="$root/hex" HEX_OFFLINE=1 \
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

# b0's conditions on the passthrough (asg_b30d5c78), enforced again by the
# preflight: the test gateway port is pinned to 0 (OS-assigned), so no suite
# gateway takes a fixed or production port such as 11373; the gate node is
# only the name scripts/verify_mix.sh makes for its own run (the same pattern
# as TestSandboxPreflight.gate_node_pattern/0), never a live node's; the gate
# claim is the literal 1.
case "${TIGHTBEAM_PORT-0}" in
  0) ;;
  *) refuse "TIGHTBEAM_PORT=$TIGHTBEAM_PORT: the test sandbox pins the gateway port to 0" ;;
esac
an='[A-Za-z0-9]'
if [ "${TIGHTBEAM_GATE_NODE+set}" = set ]; then
  # shellcheck disable=SC2254 # $an is a deliberate pattern, matched whole.
  case "$TIGHTBEAM_GATE_NODE" in
    tightbeam_mix_gate_$an$an$an$an$an$an$an$an) ;;
    *) refuse "TIGHTBEAM_GATE_NODE=$TIGHTBEAM_GATE_NODE is not a node scripts/verify_mix.sh made" ;;
  esac
fi
case "${TIGHTBEAM_AUTHORITATIVE_GATE-1}" in
  1) ;;
  *) refuse "TIGHTBEAM_AUTHORITATIVE_GATE=$TIGHTBEAM_AUTHORITATIVE_GATE is not the gate claim 1" ;;
esac

# Named, credential-free variables inherited only when the caller set them: the
# locale, the authoritative-gate claim (scripts/verify_mix.sh) and the macOS CI
# diagnostic (test/test_helper.exs). They go before the command, after env -i.
for name in LC_ALL LC_CTYPE TERM TIGHTBEAM_AUTHORITATIVE_GATE TIGHTBEAM_GATE_NODE \
  DD36_DARWIN_DIAGNOSTIC_DIR RUNNER_TEMP CANDIDATE_SHA; do
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
  MIX_HOME="$root/home/.mix" \
  HEX_HOME="$root/hex" \
  HEX_OFFLINE=1 \
  GIT_CONFIG_GLOBAL="$root/gitconfig" \
  GIT_CONFIG_NOSYSTEM=1 \
  CARGO_HOME="$root/cargo" \
  CARGO_NET_OFFLINE=true \
  TIGHTBEAM_TEST_SANDBOX="$root" \
  TIGHTBEAM_PORT=0 \
  "$@" || status=$?
exit "$status"
