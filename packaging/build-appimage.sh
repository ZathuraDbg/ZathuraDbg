#!/usr/bin/env bash
#
# build-appimage.sh - Repeatable AppImage builder for ZathuraDbg.
#
# Produces "Zathura_Debugger-x86_64.AppImage" reproducing the layout of the
# project's released AppImage:
#
#   AppDir/
#     AppRun                        bash launcher (exports LD_LIBRARY_PATH/PATH)
#     ZathuraDbg.desktop            top-level desktop entry
#     ZathuraDbg.png                top-level icon
#     .DirIcon -> ZathuraDbg.png
#     usr/bin/Zathura               the built executable
#     usr/lib/                      bundled shared libraries (allowlist below)
#     usr/assets/                   copy of repo assets/ (fonts + icon)
#     usr/vendor/ghidra/            copy of repo vendor/ghidra/ (processor specs)
#     usr/share/applications/ZathuraDbg.desktop
#     usr/share/icons/hicolor/256x256/apps/ZathuraDbg.png
#
# IMPORTANT: the binary loads data via paths relative to itself ("../assets/"
# and "../vendor/ghidra/"). With the binary at usr/bin/Zathura those resolve to
# usr/assets/ and usr/vendor/ghidra/. Do not move these.
#
# Usage:
#   bash packaging/build-appimage.sh            # build + package
#   bash packaging/build-appimage.sh --no-build # package an existing binary
#
# Environment overrides:
#   VERSION       override version (default: contents of repo VERSION file)
#   OUTPUT        output directory for the .AppImage (default: repo root)
#   STRIP         "0" to skip stripping the binary (default: strip it)
#   ARCH          target arch for appimagetool (default: x86_64)
#   CACHE_DIR     where to cache appimagetool (default: <repo>/packaging/.cache)
#
set -euo pipefail

# ----------------------------------------------------------------------------
# Locate repo root (this script lives in <repo>/packaging/).
# ----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

ARCH="${ARCH:-x86_64}"
export ARCH
OUTPUT_DIR="${OUTPUT:-${REPO_ROOT}}"
CACHE_DIR="${CACHE_DIR:-${SCRIPT_DIR}/.cache}"
STRIP_BINARY="${STRIP:-1}"
OUTPUT_NAME="Zathura_Debugger-${ARCH}.AppImage"

NO_BUILD=0
for arg in "$@"; do
    case "${arg}" in
        --no-build) NO_BUILD=1 ;;
        *) echo "Unknown argument: ${arg}" >&2; exit 2 ;;
    esac
done

# ----------------------------------------------------------------------------
# Version.
# ----------------------------------------------------------------------------
if [[ -n "${VERSION:-}" ]]; then
    APP_VERSION="${VERSION}"
elif [[ -f "${REPO_ROOT}/VERSION" ]]; then
    APP_VERSION="$(tr -d '[:space:]' < "${REPO_ROOT}/VERSION")"
else
    APP_VERSION="0.0.0"
fi
echo "==> ZathuraDbg AppImage build (version ${APP_VERSION}, arch ${ARCH})"

# ----------------------------------------------------------------------------
# 1. Build (unless --no-build).
# ----------------------------------------------------------------------------
BUILD_DIR="${REPO_ROOT}/src/build"
if [[ "${NO_BUILD}" -eq 0 ]]; then
    echo "==> Configuring and building Zathura (Release)"
    CMAKE_ARGS=(-S "${REPO_ROOT}/src" -B "${BUILD_DIR}" -G Ninja -DCMAKE_BUILD_TYPE=Release)
    # Prefer gcc-14/g++-14 when available (matches native CI), but do not hard-fail
    # if they are absent on a developer machine.
    if command -v gcc-14 >/dev/null 2>&1 && command -v g++-14 >/dev/null 2>&1; then
        CMAKE_ARGS+=(-DCMAKE_C_COMPILER=gcc-14 -DCMAKE_CXX_COMPILER=g++-14)
    fi
    cmake "${CMAKE_ARGS[@]}"
    cmake --build "${BUILD_DIR}" -j"$(nproc)"
else
    echo "==> --no-build: skipping compilation, packaging existing binary"
fi

# ----------------------------------------------------------------------------
# 2. Locate the built binary.
# ----------------------------------------------------------------------------
ZATHURA_BIN=""
for candidate in "${REPO_ROOT}/src/Zathura" "${BUILD_DIR}/Zathura"; do
    if [[ -x "${candidate}" ]]; then
        ZATHURA_BIN="${candidate}"
        break
    fi
done
if [[ -z "${ZATHURA_BIN}" ]]; then
    echo "ERROR: could not find a built Zathura binary in src/ or src/build/." >&2
    echo "       Run without --no-build, or place the binary at src/Zathura." >&2
    exit 1
fi
echo "==> Using binary: ${ZATHURA_BIN}"

# ----------------------------------------------------------------------------
# 3. Assemble AppDir.
# ----------------------------------------------------------------------------
APPDIR="${REPO_ROOT}/AppDir"
echo "==> Assembling AppDir at ${APPDIR}"
rm -rf "${APPDIR}"
mkdir -p \
    "${APPDIR}/usr/bin" \
    "${APPDIR}/usr/lib" \
    "${APPDIR}/usr/assets" \
    "${APPDIR}/usr/vendor" \
    "${APPDIR}/usr/share/applications" \
    "${APPDIR}/usr/share/icons/hicolor/256x256/apps"

# 3a. Binary.
cp -f "${ZATHURA_BIN}" "${APPDIR}/usr/bin/Zathura"
chmod +x "${APPDIR}/usr/bin/Zathura"
if [[ "${STRIP_BINARY}" != "0" ]] && command -v strip >/dev/null 2>&1; then
    echo "==> Stripping binary (set STRIP=0 to keep symbols)"
    strip --strip-unneeded "${APPDIR}/usr/bin/Zathura" || \
        echo "    (strip failed, continuing with unstripped binary)"
fi

# 3a-bis. Default sample file. The app opens "test.asm" relative to the
# executable on startup (see src/main.cpp), so it must sit next to the binary
# at usr/bin/test.asm. Without it the first launch fails to load a default file.
if [[ -f "${REPO_ROOT}/src/test.asm" ]]; then
    echo "==> Bundling default test.asm"
    cp -f "${REPO_ROOT}/src/test.asm" "${APPDIR}/usr/bin/test.asm"
else
    echo "    (warning: src/test.asm not found; AppImage will start without a default file)"
fi

# 3b. Bundle shared libraries.
#
# Strategy: ship the vendored keystone, plus an allowlist of libs that are not
# safe to assume on a target system. We deliberately do NOT bundle libc,
# libstdc++, libgcc_s, libm, libdl, the mesa GL driver (libGL), or core
# X11/xcb -- those must come from the host. This matches the released image.
LIB_ALLOWLIST=(
    libglfw.so.3
    libGLU.so.1
    libssl.so.3
    libcrypto.so.3
    libXau.so.6
    libXdmcp.so.6
    libkeystone.so.0
    libunicorn.so.2
)

in_allowlist() {
    local name="$1"
    for allowed in "${LIB_ALLOWLIST[@]}"; do
        [[ "${name}" == "${allowed}" ]] && return 0
    done
    return 1
}

echo "==> Bundling libraries into usr/lib"
# Vendored keystone (preferred source; always present in-tree).
shopt -s nullglob
for ks in "${REPO_ROOT}"/vendor/local/usr/local/lib/libkeystone.so.0*; do
    cp -Lf "${ks}" "${APPDIR}/usr/lib/libkeystone.so.0"
    echo "    + libkeystone.so.0 (vendored)"
done
shopt -u nullglob

# Everything else, derived from ldd against the real binary.
if command -v ldd >/dev/null 2>&1; then
    while read -r name _arrow path _addr; do
        # ldd lines look like: "libfoo.so.1 => /path/libfoo.so.1 (0x...)"
        [[ "${name}" == */* ]] && continue          # skip the dynamic loader line
        [[ -z "${path:-}" || "${path}" == "not" ]] && continue
        [[ -e "${path}" ]] || continue
        base="$(basename "${name}")"
        in_allowlist "${base}" || continue
        # keystone already handled from the vendored copy.
        [[ "${base}" == "libkeystone.so.0" && -e "${APPDIR}/usr/lib/libkeystone.so.0" ]] && continue
        if [[ ! -e "${APPDIR}/usr/lib/${base}" ]]; then
            cp -Lf "${path}" "${APPDIR}/usr/lib/${base}"
            echo "    + ${base} (from ${path})"
        fi
    done < <(ldd "${APPDIR}/usr/bin/Zathura" 2>/dev/null)
else
    echo "    WARNING: ldd not found; only the vendored keystone was bundled." >&2
fi

# 3c. Assets and ghidra processor specs (loaded relative to the binary).
echo "==> Copying assets and vendor/ghidra"
cp -a "${REPO_ROOT}/assets/." "${APPDIR}/usr/assets/"
cp -a "${REPO_ROOT}/vendor/ghidra/." "${APPDIR}/usr/vendor/ghidra/"

# 3d. AppRun (kept here as a heredoc so the script is self-contained).
echo "==> Writing AppRun"
cat > "${APPDIR}/AppRun" <<'APPRUN'
#!/usr/bin/bash
APPDIR="$(dirname "$(readlink -f "$0")")"
export LD_LIBRARY_PATH="$APPDIR/usr/lib:$LD_LIBRARY_PATH"
export PATH="$APPDIR/usr/bin:$PATH"
exec "$APPDIR/usr/bin/Zathura" "$@"
APPRUN
chmod +x "${APPDIR}/AppRun"

# 3e. Desktop entry (top-level + usr/share/applications).
echo "==> Writing desktop entry"
write_desktop() {
    cat > "$1" <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=Zathura Debugger
Exec=Zathura
Icon=ZathuraDbg
Categories=Development;
DESKTOP
}
write_desktop "${APPDIR}/ZathuraDbg.desktop"
write_desktop "${APPDIR}/usr/share/applications/ZathuraDbg.desktop"

# 3f. Icon (top-level + hicolor) + .DirIcon symlink.
echo "==> Placing icon"
ICON_SRC="${REPO_ROOT}/assets/ZathuraDbg.png"
if [[ ! -f "${ICON_SRC}" ]]; then
    echo "ERROR: icon not found at ${ICON_SRC}" >&2
    exit 1
fi
cp -f "${ICON_SRC}" "${APPDIR}/ZathuraDbg.png"
cp -f "${ICON_SRC}" "${APPDIR}/usr/share/icons/hicolor/256x256/apps/ZathuraDbg.png"
ln -sf "ZathuraDbg.png" "${APPDIR}/.DirIcon"

# ----------------------------------------------------------------------------
# 4. Fetch appimagetool (cached) and build the AppImage.
# ----------------------------------------------------------------------------
mkdir -p "${CACHE_DIR}"
APPIMAGETOOL="${CACHE_DIR}/appimagetool-${ARCH}.AppImage"
if [[ ! -x "${APPIMAGETOOL}" ]]; then
    echo "==> Downloading appimagetool"
    URL="https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-${ARCH}.AppImage"
    if command -v curl >/dev/null 2>&1; then
        curl -fSL "${URL}" -o "${APPIMAGETOOL}"
    else
        wget -O "${APPIMAGETOOL}" "${URL}"
    fi
    chmod +x "${APPIMAGETOOL}"
fi

mkdir -p "${OUTPUT_DIR}"
OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"
echo "==> Running appimagetool"
# --appimage-extract-and-run avoids needing FUSE (important in CI containers).
# Pass VERSION through so appimagetool can embed it.
VERSION="${APP_VERSION}" "${APPIMAGETOOL}" --appimage-extract-and-run \
    "${APPDIR}" "${OUTPUT_PATH}"

# ----------------------------------------------------------------------------
# 5. Report.
# ----------------------------------------------------------------------------
echo ""
echo "==> Done."
echo "    Output: ${OUTPUT_PATH}"
ls -la "${OUTPUT_PATH}"
