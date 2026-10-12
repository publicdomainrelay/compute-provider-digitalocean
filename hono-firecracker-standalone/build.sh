#!/bin/sh
set -eu

# Builds the firecracker runner image in a build directory of its own and tags
# it by the sha256 of everything that goes into it, so two builds never share a
# build context and a rebuild never changes the image a running bed pinned.
# Prints the content tag on stdout; everything else goes to stderr.
#
# NODEBOOT_SRC      the socialweb-computer-kcp checkout socialweb-nodeboot is built from
# FIRECRACKER       the firecracker binary copied into the image
# RUNNER_REPO       the repository part of the tag (default localhost/socialweb-firecracker-runner)
# RUNNER_BUILD_DIR  the build context (default a temp dir, removed after)
# RUNNER_IMAGE      an extra tag to put on the result (optional)

HERE=$(cd "$(dirname "$0")" && pwd)
NODEBOOT_SRC=${NODEBOOT_SRC:-$HERE/../../socialweb-computer-kcp}
FIRECRACKER=${FIRECRACKER:-$HOME/kcp-image/artifacts/bin/firecracker}
RUNNER_REPO=${RUNNER_REPO:-localhost/socialweb-firecracker-runner}
BUILD_DIR=${RUNNER_BUILD_DIR:-}
CLEANUP=""
if [ -z "$BUILD_DIR" ]; then
  BUILD_DIR=$(mktemp -d)
  CLEANUP=$BUILD_DIR
fi
trap '[ -n "$CLEANUP" ] && rm -rf "$CLEANUP"' EXIT

case "$BUILD_DIR" in
  "$HERE"|"$HERE"/*)
    echo "RUNNER_BUILD_DIR $BUILD_DIR is inside the source tree; pick a directory of its own" >&2
    exit 1
    ;;
esac

mkdir -p "$BUILD_DIR"
cp "$HERE/Dockerfile" "$HERE/entrypoint.sh" "$BUILD_DIR/"
CGO_ENABLED=0 go build -C "$NODEBOOT_SRC" -trimpath -buildvcs=false -o "$BUILD_DIR/socialweb-nodeboot" ./cmd/socialweb-nodeboot
install -m 0755 "$FIRECRACKER" "$BUILD_DIR/firecracker"

HASH=$(cd "$BUILD_DIR" && sha256sum Dockerfile entrypoint.sh socialweb-nodeboot firecracker | sha256sum | cut -c1-12)
TAG=$RUNNER_REPO:sha-$HASH
if docker image inspect "$TAG" >/dev/null 2>&1; then
  echo "runner image $TAG already built" >&2
else
  docker build -q -t "$TAG" "$BUILD_DIR" >&2
fi
if [ -n "${RUNNER_IMAGE:-}" ]; then
  docker tag "$TAG" "$RUNNER_IMAGE"
fi
echo "$TAG"
