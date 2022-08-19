#!/bin/sh
set -e

log() {
    echo "libxdp: $*"
}


CURRENT_SOURCE_DIR="$1"
CURRENT_BUILD_DIR="$2"
shift 2

BUILD_LOG=$(realpath "$CURRENT_BUILD_DIR/libxdp-build.log")
rm -f "$BUILD_LOG"
log "see $BUILD_LOG for full build log"

(
    cd $CURRENT_SOURCE_DIR

    # configure xdp tools for release build and not using a system-wide libbpf
    # instead it will download and build a compatible version of libbpf to
    # current libxdp version
    log "running configure..."
    FORCE_SUBDIR_LIBBPF=1 PRODUCTION=1 ./configure >>"$BUILD_LOG" 2>&1

    # FIXME: (mansour) fix this build process:
    # - We need both a static build (.a), and a shared build (.so):
    #    * A static build is used with our CI-Example socket profiler program.
    #    * A shared build is used in gramine runtime within gramine.
    #
    # - Are both (libxdp & libbpf) needed? Figure that out.

    log "running make..."
    BUILD_STATIC_ONLY=y make -j"$(nproc)" libxdp >>"$BUILD_LOG" 2>&1

    cp lib/libxdp/libxdp.a $CURRENT_BUILD_DIR
    cp lib/libbpf/src/libbpf.a $CURRENT_BUILD_DIR
)

log "done"
