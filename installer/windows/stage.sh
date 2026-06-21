#!/usr/bin/env bash
# Assemble the Windows install tree that installer/windows/zathura.iss packages.
# Run inside the MSYS2 MINGW64 shell after building (see COMPILE.md).
#
#   <staging>/bin/      Zathura.exe + every DLL it links (MinGW runtime + glfw,
#                       keystone, capstone, icicle, ...)
#   <staging>/assets/   fonts, ZathuraDbg.png, ZathuraIcon.ico
#
# Usage:
#   installer/windows/stage.sh <path-to-built-Zathura.exe> [staging-dir]
# e.g.
#   installer/windows/stage.sh src/build/Zathura.exe installer/windows/staging
set -euo pipefail

EXE="${1:?usage: stage.sh <Zathura.exe> [staging-dir]}"
STAGING="${2:-installer/windows/staging}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

[ -f "$EXE" ] || { echo "stage.sh: exe not found: $EXE" >&2; exit 1; }

rm -rf "$STAGING"
mkdir -p "$STAGING/bin" "$STAGING/assets"

cp "$EXE" "$STAGING/bin/"
EXE_DIR="$(cd "$(dirname "$EXE")" && pwd)"

# (1) System MinGW DLLs the EXE links — resolved with ldd so the list can never
# drift the way the old hand-maintained one did (it was missing libcapstone /
# libunicorn). We only take DLLs from the MinGW/UCRT prefix; Windows\System32
# DLLs are part of the OS and must NOT be bundled.
ldd "$EXE" | awk '{print $3}' | grep -iE '/(mingw64|ucrt64|clang64)/' | while read -r dll; do
  [ -f "$dll" ] && cp -u "$dll" "$STAGING/bin/"
done

# (2) Project-built DLLs (e.g. icicle.dll from vendor/icicle-cpp) live in the
# CMake build tree, not in mingw64/bin, so ldd may not resolve them. Copy every
# DLL beside the EXE and anywhere under the build tree.
copy_dlls_from() { [ -d "$1" ] && find "$1" -name '*.dll' -exec cp -u {} "$STAGING/bin/" \; 2>/dev/null || true; }
copy_dlls_from "$EXE_DIR"
copy_dlls_from "$REPO_ROOT/src/build"

# (3) Runtime assets — the EXE loads ..\assets relative to itself, so they sit
# beside bin\. Includes the window-icon PNG and the installer/shortcut .ico.
cp -r "$REPO_ROOT/assets/." "$STAGING/assets/"

echo "== staged into $STAGING =="
( cd "$STAGING" && find . -type f | sort | sed 's/^/  /' )
echo "== bin DLL count: $(find "$STAGING/bin" -name '*.dll' | wc -l) =="
