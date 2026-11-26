#!/usr/bin/env bash
# docker-operator.sh -- one-command Linux+bubblewrap runner for macOS/container evaluators.
# Builds the local Ubuntu 24.04 + bubblewrap image on demand and executes bin/operator.sh
# inside a namespace-capable container with optional persistent state under OPERATOR_DOCKER_STATE.
#
# usage:
#   scripts/docker-operator.sh [--rebuild] [--mount <host-dir>] [--publish-panel]
#                              [--ephemeral-state] [--allow-linux-unconfined] [<operator-args...>]
#   scripts/docker-operator.sh --selftest
# default command when no operator args are given: `demo run`
# exit: tool exit code, or 2 on usage / missing docker / invalid mount
set -uo pipefail

HERE=$(cd -- "$(dirname -- "$(readlink -f -- "$0")")" && pwd)
ROOT=$(cd -- "$HERE/.." && pwd)
DOCKER_BIN="${OPERATOR_DOCKER_BIN:-docker}"

HOST_UID=$(id -u)
HOST_GID=$(id -g)
BUILD_UID=10001
BUILD_GID=10001
DEFAULT_IMAGE="operator-control-plane:local"
if [ "$(uname -s)" = "Linux" ] && [ "$HOST_UID" != "0" ]; then
  BUILD_UID="$HOST_UID"
  BUILD_GID="$HOST_GID"
  DEFAULT_IMAGE="operator-control-plane:local-${HOST_UID}-${HOST_GID}"
fi
IMAGE="${OPERATOR_DOCKER_IMAGE:-$DEFAULT_IMAGE}"

die() { echo "docker-operator: $*" >&2; exit 2; }

check_mount_path() {
  case "$1" in
    *,*|*$'\n'*|*$'\r'*) die "mount path may not contain commas or newlines: $1" ;;
  esac
}

selftest() {
  local rc=0 T out r st_mode
  me=$(readlink -f -- "$0")
  T=$(mktemp -d) || exit 2
  trap 'rm -rf "${T:?}"' EXIT
  # A missing docker binary refuses with rc 2
  mkdir -p "$T/empty"
  out=$(OPERATOR_HOST_OS=Darwin OPERATOR_DOCKER_BIN="$T/empty/no-docker" "$me" demo run 2>&1); r=$?
  { [ "$r" = 2 ] && printf '%s' "$out" | grep -q "docker"; } || { echo "A missing docker: rc=$r [$out]"; rc=1; }
  # A2 native Linux host refuses without --allow-linux-unconfined override
  out=$(OPERATOR_HOST_OS=Linux OPERATOR_ALLOW_LINUX_DOCKER=0 OPERATOR_DOCKER_BIN="$T/empty/no-docker" "$me" demo run 2>&1); r=$?
  { [ "$r" = 2 ] && printf '%s' "$out" | grep -q "allow-linux-unconfined"; } \
    || { echo "A2 Linux unconfined guard: rc=$r [$out]"; rc=1; }
  # B missing --mount target refuses before invoking docker
  cat > "$T/fake-docker" <<'EOF'
#!/bin/sh
if [ "$1" = "image" ] && [ "$2" = "inspect" ]; then exit 0; fi
printf 'DOCKER:%s\n' "$*"
exit 0
EOF
  chmod +x "$T/fake-docker"
  out=$(OPERATOR_HOST_OS=Darwin OPERATOR_DOCKER_BIN="$T/fake-docker" OPERATOR_DOCKER_STATE="$T/st" "$me" --mount "$T/nosuch" demo run 2>&1); r=$?
  { [ "$r" = 2 ] && printf '%s' "$out" | grep -q "mount"; } || { echo "B bad mount: rc=$r [$out]"; rc=1; }
  # C default args run `demo run` with bwrap namespace opts, type=bind to /operator-state, and 0700 state dir
  mkdir -p "$T/ws"
  out=$(OPERATOR_HOST_OS=Linux OPERATOR_DOCKER_BIN="$T/fake-docker" OPERATOR_DOCKER_STATE="$T/st2" "$me" --allow-linux-unconfined --publish-panel --mount "$T/ws" 2>&1); r=$?
  st_mode=$(python3 -c 'import os,sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777))' "$T/st2")
  { [ "$r" = 0 ] && [ "$st_mode" = "0o700" ] \
      && printf '%s' "$out" | grep -q "seccomp=unconfined" \
      && printf '%s' "$out" | grep -q "systempaths=unconfined" \
      && printf '%s' "$out" | grep -q "127.0.0.1:8765:8765" \
      && printf '%s' "$out" | grep -q "OPERATOR_PANEL_BIND=0.0.0.0" \
      && printf '%s' "$out" | grep -q "dst=/operator-state" \
      && printf '%s' "$out" | grep -q "demo run"; } \
    || { echo "C default demo run: rc=$r mode=$st_mode [$out]"; rc=1; }
  # D Dockerfile exists and names bubblewrap, /operator-state, and non-root USER
  { [ -f "$ROOT/Dockerfile" ] && grep -q "bubblewrap" "$ROOT/Dockerfile" \
      && grep -q "^USER runner" "$ROOT/Dockerfile" \
      && grep -q "OPERATOR_HOME=/operator-state" "$ROOT/Dockerfile"; } \
    || { echo "D Dockerfile check failed"; rc=1; }
  if [ "$rc" = 0 ]; then echo "selftest: OK (missing docker, mount validation, 0700 state, bwrap caps, Dockerfile)"; else echo "selftest: FAIL"; fi
  exit "$rc"
}

[ "${1:-}" = "--selftest" ] && selftest

REBUILD=0
MOUNT_DIR=""
ALLOW_LINUX=0
PUBLISH_PANEL=0
EPHEMERAL_STATE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --rebuild) REBUILD=1; shift ;;
    --allow-linux-unconfined) ALLOW_LINUX=1; shift ;;
    --publish-panel) PUBLISH_PANEL=1; shift ;;
    --ephemeral-state) EPHEMERAL_STATE=1; shift ;;
    --mount)
      [ $# -ge 2 ] || die "--mount needs a directory path"
      [ -d "$2" ] || die "--mount directory does not exist: $2"
      MOUNT_DIR=$(cd -- "$2" && pwd) || die "cannot resolve --mount: $2"
      check_mount_path "$MOUNT_DIR"
      shift 2 ;;
    --help|-h)
      sed -n '2,/^set -/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) break ;;
  esac
done

HOST_OS="${OPERATOR_HOST_OS:-$(uname -s)}"
if [ "$HOST_OS" = "Linux" ] && [ "$ALLOW_LINUX" != 1 ] && [ "${OPERATOR_ALLOW_LINUX_DOCKER:-0}" != "1" ]; then
  die "on native Linux, run ./bin/operator.sh directly with bubblewrap (nested bwrap in Docker requires unconfined seccomp/systempaths against the host kernel; pass --allow-linux-unconfined to override)"
fi

if [ "$EPHEMERAL_STATE" = 1 ]; then
  OPERATOR_DOCKER_STATE=""
elif [ -z "${OPERATOR_DOCKER_STATE:-}" ] && [ -n "${HOME:-}" ]; then
  OPERATOR_DOCKER_STATE="${XDG_STATE_HOME:-$HOME/.local/state}/operator-docker"
fi

command -v "$DOCKER_BIN" >/dev/null 2>&1 || [ -x "$DOCKER_BIN" ] \
  || die "docker not found ($DOCKER_BIN); install Docker Desktop or Colima first"

if [ "$REBUILD" = 1 ] || ! "$DOCKER_BIN" image inspect "$IMAGE" >/dev/null 2>&1; then
  "$DOCKER_BIN" build \
    --build-arg "USER_UID=$BUILD_UID" \
    --build-arg "USER_GID=$BUILD_GID" \
    -t "$IMAGE" "$ROOT" || die "docker build failed"
fi

EXTRA_ARGS=()
if [ -n "${OPERATOR_DOCKER_STATE:-}" ]; then
  if [ ! -d "$OPERATOR_DOCKER_STATE" ]; then
    if ! { mkdir -p "$(dirname -- "$OPERATOR_DOCKER_STATE")" && mkdir -m 0700 "$OPERATOR_DOCKER_STATE"; }; then
      die "cannot create state dir $OPERATOR_DOCKER_STATE"
    fi
    if [ "$(uname -s)" = "Linux" ] && [ "$HOST_UID" = "0" ]; then
      chown 10001:10001 "$OPERATOR_DOCKER_STATE" || die "cannot chown $OPERATOR_DOCKER_STATE"
    fi
  fi
  STATE_ABS=$(cd -- "$OPERATOR_DOCKER_STATE" && pwd) || die "cannot resolve $OPERATOR_DOCKER_STATE"
  check_mount_path "$STATE_ABS"
  EXTRA_ARGS+=(--mount "type=bind,src=$STATE_ABS,dst=/operator-state")
fi
if [ -n "$MOUNT_DIR" ]; then
  EXTRA_ARGS+=(--mount "type=bind,src=$MOUNT_DIR,dst=/workspace")
fi
if [ "$PUBLISH_PANEL" = 1 ]; then
  EXTRA_ARGS+=(-e "OPERATOR_PANEL_BIND=0.0.0.0" -p "127.0.0.1:8765:8765")
fi

if [ $# -eq 0 ]; then
  set -- demo run
fi

exec "$DOCKER_BIN" run --rm --init \
  --cap-add SYS_ADMIN \
  --cap-add NET_ADMIN \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  --security-opt systempaths=unconfined \
  "${EXTRA_ARGS[@]}" \
  "$IMAGE" "$@"
