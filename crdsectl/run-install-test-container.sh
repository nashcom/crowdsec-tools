#!/bin/bash

# Test container with systemd as PID 1, so crdsectl.sh's systemctl/journalctl
# paths (install/status/reload/restart/systemd/log) have something to talk to.
#
# -redhat / -rhel   pull registry.access.redhat.com/ubi10-init (systemd built in)
# -ubuntu           build ./Dockerfile locally (ubuntu:latest + systemd installed)
# IMAGE_MODE env var sets the default when no flag is given.
#
# stop              docker stop the running container - leaves it around, can
#                   be started again with "docker start -ai crdsectl-test"
# rm                docker rm -f the container - stops (if needed) and deletes
#                   it, but keeps any built/pulled image (rerun this script
#                   with no args to build a fresh container from it)
# kill              docker kill the container (SIGKILL, immediate, no
#                   graceful shutdown) - for when "stop" hangs
#
# NETWORK_MODE env var: "host" (default) or "bridge".
#   host    --network host - "localhost" reaches services published on the
#           real host (e.g. the crdsec-hub's nginx), and nftables
#           rules apply to the real host network stack, not a sandbox.
#   bridge  joins the shared crowdsec-net network instead (also used by
#           ../crdsec-hub/docker-compose.yml) - reach the hub via its
#           container name (e.g. https://crowdsec-nginx:443) rather than
#           localhost. Narrower blast radius, but less like how a real
#           Domino server (never on the hub's Docker network) reaches it.
#
# crdsectl.sh lives alongside this script, but /local is mounted at the repo
# root (not this directory) so the notesdata/ test fixture is also visible
# at /local/notesdata, matching DOMINO_DATA_PATH's default. That makes
# crdsectl.sh reachable in the container at /local/crdsectl/crdsectl.sh.
# SCRIPT_DIR/REPO_ROOT make the build context and the /local bind mount
# work regardless of the directory this is invoked from.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)

case "$1" in
  help|-h|--help)
    echo
    echo "run-install-test-container.sh"
    echo "------------------------------"
    echo
    echo "Syntax: run-install-test-container.sh [option]"
    echo
    printf "  %-12s%s\n" "-ubuntu" "Build ./Dockerfile locally (ubuntu:latest + systemd installed) - default"
    printf "  %-12s%s\n" "-redhat" "Pull registry.access.redhat.com/ubi10-init (systemd built in)"
    printf "  %-12s%s\n" "stop" "docker stop the running container - leaves it around"
    printf "  %-12s%s\n" "rm" "docker rm -f the container - stops (if needed) and deletes it"
    printf "  %-12s%s\n" "kill" "docker kill the container (SIGKILL) - for when \"stop\" hangs"
    printf "  %-12s%s\n" "help" "Show this help"
    echo
    echo "Env vars: IMAGE_MODE (ubuntu|rhel, default ubuntu), NETWORK_MODE (host|bridge, default host)"
    echo
    exit 0
    ;;

  stop)
    docker stop crdsectl-test
    exit $?
    ;;

  rm)
    docker rm -f crdsectl-test
    exit $?
    ;;

  kill)
    docker kill crdsectl-test
    exit $?
    ;;
esac

IMAGE_MODE="${IMAGE_MODE:-ubuntu}"

case "$1" in
  -redhat|-rhel)
    IMAGE_MODE="rhel"
    ;;

  -ubuntu)
    IMAGE_MODE="ubuntu"
    ;;

  "")
    ;;

  *)
    echo "Unknown option: $1 (use -redhat, -ubuntu, stop, rm, kill, or help)" >&2
    exit 1
    ;;
esac

RHEL_IMAGE="registry.access.redhat.com/ubi10-init:latest"
UBUNTU_IMAGE_TAG="crdsectl-systemd:ubuntu"

docker stop crdsectl-test 2>/dev/null
docker rm crdsectl-test 2>/dev/null

case "$IMAGE_MODE" in
  rhel)
    echo "Pulling $RHEL_IMAGE (first pull can take a few minutes) ..."
    BASE_IMAGE="$RHEL_IMAGE"
    ;;

  ubuntu)
    echo
    echo "Building $UBUNTU_IMAGE_TAG from ./Dockerfile (ubuntu + systemd + dbus + tools)."
    echo "This can take a few minutes on the first build, less once Docker's cache is warm."
    echo
    docker build --progress=plain -t "$UBUNTU_IMAGE_TAG" "$SCRIPT_DIR" || exit 1
    BASE_IMAGE="$UBUNTU_IMAGE_TAG"
    ;;

  *)
    echo "Unknown IMAGE_MODE: $IMAGE_MODE (use 'rhel' or 'ubuntu')" >&2
    exit 1
    ;;
esac

NETWORK_MODE="${NETWORK_MODE:-host}"

case "$NETWORK_MODE" in
  host)
    # Docker rejects --hostname together with --network host (the
    # container just sees the real host's hostname).
    NETWORK_ARGS="--network host"
    ;;

  bridge)
    # Shared with the crowdsec-net network ../crdsec-hub/docker-compose.yml
    # also creates/owns itself (not external) - created here too, idempotently,
    # so whichever side starts first doesn't fail on a missing network.
    docker network create crowdsec-net >/dev/null 2>&1
    NETWORK_ARGS="--network crowdsec-net --hostname crdsectl-test"
    ;;

  *)
    echo "Unknown NETWORK_MODE: $NETWORK_MODE (use 'host' or 'bridge')" >&2
    exit 1
    ;;
esac

# Detached, no command override: let the image's own entrypoint (/sbin/init)
# boot systemd as PID 1. Attach with "docker exec -it crdsectl-test bash".
echo "Starting crdsectl-test container ($BASE_IMAGE, network: $NETWORK_MODE) ..."
docker run -d --name crdsectl-test $NETWORK_ARGS --privileged -v "${REPO_ROOT}:/local" "$BASE_IMAGE"
docker exec -it crdsectl-test bash
