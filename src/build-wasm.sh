#!/usr/bin/env bash
# Configure and build the Emscripten/wasm version of ZathuraDbg.
#
# Prereqs (built once, see /home/rc/icicle-wasm):
#   - libicicle.a  (wasm32-unknown-emscripten, interpreter-only)
#   - libkeystone.a, libcapstone.a (emcc-built)
#   - zathura-fs/  (MEMFS staging: app/bin, app/assets, ghidra specs)
set -euo pipefail
cd "$(dirname "$0")"

# Defaults assume the icicle-wasm workspace sits next to this repo. Override via
# the environment if it lives elsewhere.
WASM_LIBS_ROOT="${WASM_LIBS_ROOT:-$(cd ../../icicle-wasm && pwd)}"
EMSDK_ENV="${EMSDK_ENV:-$WASM_LIBS_ROOT/emsdk/emsdk_env.sh}"
BUILD_DIR="${BUILD_DIR:-build-wasm}"

if [[ ! -f "$EMSDK_ENV" ]]; then
    echo "error: emsdk_env.sh not found at $EMSDK_ENV" >&2
    echo "set EMSDK_ENV=/path/to/emsdk/emsdk_env.sh (and WASM_LIBS_ROOT)" >&2
    exit 1
fi

# shellcheck disable=SC1090
source "$EMSDK_ENV" >/dev/null 2>&1

emcmake cmake -S . -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DWASM_LIBS_ROOT="$WASM_LIBS_ROOT"

cmake --build "$BUILD_DIR" --target Zathura -j"$(nproc)"

echo
echo "Built: $PWD/Zathura.html (+ .js/.wasm/.data)"
echo "Serve from this directory, e.g.:"
echo "  uv run python -m http.server 8090 --bind 127.0.0.1"
