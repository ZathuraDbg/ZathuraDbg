#!/usr/bin/env bash
# Configure and build the Emscripten/wasm version of ZathuraDbg.
#
# Prereqs (built once, see /home/rc/icicle-wasm):
#   - libicicle.a  (wasm32-unknown-emscripten, interpreter-only)
#   - libkeystone.a, libcapstone.a (emcc-built)
#   - zathura-fs/  (MEMFS staging: app/bin, app/assets, ghidra specs)
set -euo pipefail
cd "$(dirname "$0")"

EMSDK_ENV="${EMSDK_ENV:-/home/rc/icicle-wasm/emsdk/emsdk_env.sh}"
WASM_LIBS_ROOT="${WASM_LIBS_ROOT:-/home/rc/icicle-wasm}"
BUILD_DIR="${BUILD_DIR:-build-wasm}"

# shellcheck disable=SC1090
source "$EMSDK_ENV" >/dev/null 2>&1

emcmake cmake -S . -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DWASM_LIBS_ROOT="$WASM_LIBS_ROOT"

cmake --build "$BUILD_DIR" --target Zathura -j"$(nproc)"

echo
echo "Built: $BUILD_DIR/Zathura.html (+ .js/.wasm/.data)"
echo "Serve with COOP/COEP-agnostic static server, e.g.:"
echo "  emrun --no_browser --port 8080 $BUILD_DIR/Zathura.html"
