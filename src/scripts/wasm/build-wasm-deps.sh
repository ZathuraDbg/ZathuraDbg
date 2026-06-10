#!/usr/bin/env bash
# Reproducibly build the out-of-tree dependencies the wasm app links against:
#   - libcapstone.a   (capstone 5.0.1, headers used for cs_* enums)
#   - libkeystone.a   (vendored vendor/keystone)
#   - libicicle.a     (icicle-emu @ pinned commit + vendored wasm patch, jit off)
#   - unicorn headers (UC_* enums only)
#   - zathura-fs/     (MEMFS staging: fonts, sample asm, sleigh specs, layout)
#
# Output goes under $WASM_LIBS_ROOT (default: a sibling icicle-wasm/ dir), the
# same root src/CMakeLists.txt and build-wasm.sh default to. Each step is
# skip-if-present so CI caching of $WASM_LIBS_ROOT makes reruns cheap.
#
# Requires: an activated emsdk (emcc/emcmake on PATH) and the
# wasm32-unknown-emscripten Rust target.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"          # repo/src
REPO_DIR="$(cd "$SRC_DIR/.." && pwd)"               # repo root
WASM_LIBS_ROOT="${WASM_LIBS_ROOT:-$SRC_DIR/../../icicle-wasm}"
CAPSTONE_TAG="${CAPSTONE_TAG:-5.0.1}"

mkdir -p "$WASM_LIBS_ROOT"
WASM_LIBS_ROOT="$(cd "$WASM_LIBS_ROOT" && pwd)"
echo "Building wasm deps into: $WASM_LIBS_ROOT"

command -v emcc >/dev/null || { echo "error: emcc not on PATH (source emsdk_env.sh)" >&2; exit 1; }
rustup target list --installed 2>/dev/null | grep -q wasm32-unknown-emscripten \
    || rustup target add wasm32-unknown-emscripten

# --- capstone -----------------------------------------------------------------
if [[ ! -f "$WASM_LIBS_ROOT/capstone/build-wasm/libcapstone.a" ]]; then
    echo ">>> capstone $CAPSTONE_TAG"
    [[ -d "$WASM_LIBS_ROOT/capstone" ]] || \
        git clone --depth 1 -b "$CAPSTONE_TAG" https://github.com/capstone-engine/capstone "$WASM_LIBS_ROOT/capstone"
    emcmake cmake -S "$WASM_LIBS_ROOT/capstone" -B "$WASM_LIBS_ROOT/capstone/build-wasm" \
        -DCMAKE_BUILD_TYPE=Release -DCAPSTONE_BUILD_TESTS=OFF -DCAPSTONE_BUILD_CSTOOL=OFF \
        -DBUILD_SHARED_LIBS=OFF -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF \
        -DCAPSTONE_X86_SUPPORT=ON -DCAPSTONE_ARM_SUPPORT=ON -DCAPSTONE_AARCH64_SUPPORT=ON
    cmake --build "$WASM_LIBS_ROOT/capstone/build-wasm" -j"$(nproc)"
fi

# --- keystone (from vendored source) ------------------------------------------
if [[ ! -f "$WASM_LIBS_ROOT/keystone-src/build-wasm/llvm/lib/libkeystone.a" ]]; then
    echo ">>> keystone (vendored)"
    rm -rf "$WASM_LIBS_ROOT/keystone-src"
    cp -r "$REPO_DIR/vendor/keystone" "$WASM_LIBS_ROOT/keystone-src"
    emcmake cmake -S "$WASM_LIBS_ROOT/keystone-src" -B "$WASM_LIBS_ROOT/keystone-src/build-wasm" \
        -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
        -DLLVM_TARGETS_TO_BUILD="X86;AArch64;ARM" -DBUILD_LIBS_ONLY=ON
    cmake --build "$WASM_LIBS_ROOT/keystone-src/build-wasm" -j"$(nproc)"
fi

# --- unicorn headers (enums only) ---------------------------------------------
if [[ ! -d "$WASM_LIBS_ROOT/unicorn-include/unicorn" ]]; then
    echo ">>> unicorn headers"
    tmp="$(mktemp -d)"
    git clone --depth 1 https://github.com/unicorn-engine/unicorn "$tmp/unicorn"
    mkdir -p "$WASM_LIBS_ROOT/unicorn-include"
    cp -r "$tmp/unicorn/include/unicorn" "$WASM_LIBS_ROOT/unicorn-include/"
    rm -rf "$tmp"
fi

# --- icicle (patched fork + bindings) -----------------------------------------
if [[ ! -f "$WASM_LIBS_ROOT/icicle-cpp/src/target/wasm32-unknown-emscripten/release/libicicle.a" ]]; then
    echo ">>> icicle-emu (pinned + wasm patch)"
    ICICLE_COMMIT="$(cat "$SCRIPT_DIR/icicle-emu-commit.txt")"
    rm -rf "$WASM_LIBS_ROOT/icicle-emu"
    git clone https://github.com/icicle-emu/icicle-emu "$WASM_LIBS_ROOT/icicle-emu"
    git -C "$WASM_LIBS_ROOT/icicle-emu" checkout -q "$ICICLE_COMMIT"
    git -C "$WASM_LIBS_ROOT/icicle-emu" apply "$SCRIPT_DIR/icicle-emu-wasm.patch"

    echo ">>> icicle-cpp bindings (vendored + wasm patch)"
    rm -rf "$WASM_LIBS_ROOT/icicle-cpp"
    cp -r "$REPO_DIR/vendor/icicle-cpp" "$WASM_LIBS_ROOT/icicle-cpp"
    git -C "$WASM_LIBS_ROOT/icicle-cpp" apply "$SCRIPT_DIR/icicle-cpp-wasm.patch" 2>/dev/null \
        || ( cd "$WASM_LIBS_ROOT/icicle-cpp" && patch -p1 < "$SCRIPT_DIR/icicle-cpp-wasm.patch" )

    ( cd "$WASM_LIBS_ROOT/icicle-cpp/src" && \
      cargo build --release --target wasm32-unknown-emscripten --no-default-features )
fi

# --- MEMFS staging ------------------------------------------------------------
echo ">>> staging zathura-fs"
FS="$WASM_LIBS_ROOT/zathura-fs"
rm -rf "$FS"
mkdir -p "$FS/app/bin" "$FS/app/assets" "$FS/ghidra/Ghidra/Processors"
cp "$SRC_DIR/test.asm" "$FS/app/bin/test.asm"
cp "$SRC_DIR/wasm-default-layout.zlyt" "$FS/app/config.zlyt"
cp -r "$REPO_DIR/assets/." "$FS/app/assets/"
for arch in x86 AARCH64 ARM; do
    mkdir -p "$FS/ghidra/Ghidra/Processors/$arch/data"
    cp -r "$REPO_DIR/vendor/ghidra/Ghidra/Processors/$arch/data/languages" \
        "$FS/ghidra/Ghidra/Processors/$arch/data/"
done

echo
echo "Done. libicicle / libkeystone / libcapstone + zathura-fs are in $WASM_LIBS_ROOT"
echo "Now run:  ./build-wasm.sh"
