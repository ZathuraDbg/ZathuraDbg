#!/usr/bin/env bash
# Memory-safe build wrapper. Prefer this over "make -j$(nproc)".
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
build_dir="${root}/build"
generator="Ninja"

if ! command -v ninja >/dev/null 2>&1; then
    generator="Unix Makefiles"
fi

mkdir -p "${build_dir}"
cmake -S "${root}" -B "${build_dir}" -G "${generator}" "$@"
cmake --build "${build_dir}"
