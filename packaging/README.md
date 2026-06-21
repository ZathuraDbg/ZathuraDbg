# Packaging ZathuraDbg as an AppImage

This directory contains a repeatable build + publishing pipeline that produces
`Zathura_Debugger-x86_64.AppImage`, reproducing the layout of the project's
released AppImage.

## Build locally

```bash
bash packaging/build-appimage.sh
```

This will:

1. Read the version from the repo `VERSION` file (override with `VERSION=...`).
2. Configure + build a Release `Zathura` with CMake/Ninja
   (`cmake -S src -B src/build -G Ninja -DCMAKE_BUILD_TYPE=Release`, then
   `cmake --build src/build`). gcc-14/g++-14 are used when available, matching CI.
3. Assemble an `AppDir/` and run `appimagetool` to emit
   `Zathura_Debugger-x86_64.AppImage` in the repo root.

`appimagetool` is downloaded once into `packaging/.cache/` (git-ignored) and is
invoked with `--appimage-extract-and-run`, so **FUSE is not required** (works in
CI containers).

### Packaging a prebuilt binary

If you already have a built binary at `src/Zathura` (or `src/build/Zathura`) and
just want to repackage:

```bash
bash packaging/build-appimage.sh --no-build
```

### Useful environment overrides

| Variable    | Default                     | Meaning                                   |
|-------------|-----------------------------|-------------------------------------------|
| `VERSION`   | contents of `VERSION` file  | version embedded by appimagetool          |
| `OUTPUT`    | repo root                   | output directory for the `.AppImage`      |
| `STRIP`     | `1` (strip)                 | set `0` to keep debug symbols in binary   |
| `ARCH`      | `x86_64`                    | target architecture                       |
| `CACHE_DIR` | `packaging/.cache`          | where `appimagetool` is cached            |

## Publishing (push a tag)

Publishing is fully automated by `.github/workflows/appimage.yml`, which is
triggered **only on tag pushes**:

```bash
git tag v1.0
git push origin v1.0
```

The workflow runs on `ubuntu-latest`, installs the apt build deps, runs
`packaging/build-appimage.sh`, and uploads the resulting
`Zathura_Debugger-x86_64.AppImage` to the GitHub Release for that tag via
`softprops/action-gh-release@v2` (using the built-in `GITHUB_TOKEN`;
the job has `permissions: contents: write`).

## AppDir layout

```
AppDir/
  AppRun                         bash launcher (exports LD_LIBRARY_PATH/PATH, execs the binary)
  ZathuraDbg.desktop             top-level desktop entry
  ZathuraDbg.png                 top-level icon
  .DirIcon -> ZathuraDbg.png
  usr/bin/Zathura                the built executable
  usr/lib/                       bundled shared libraries (see below)
  usr/assets/                    copy of repo assets/ (fonts + icon)
  usr/vendor/ghidra/             copy of repo vendor/ghidra/ (processor specs)
  usr/share/applications/ZathuraDbg.desktop
  usr/share/icons/hicolor/256x256/apps/ZathuraDbg.png
```

**Critical:** ZathuraDbg loads its data via paths *relative to the executable* —
`../assets/...` for fonts/icon and `../vendor/ghidra/` for processor specs (see
`src/main.cpp`). With the binary at `usr/bin/Zathura` these resolve to
`usr/assets/` and `usr/vendor/ghidra/`. Do not move these directories.

## Library bundling and glibc notes

The AppImage bundles only libraries that cannot be assumed present on a target
system. The vendored keystone (`vendor/local/usr/local/lib/libkeystone.so.0`) is
always bundled; everything else is derived from `ldd` against the built binary
and filtered through an allowlist:

```
libglfw.so.3  libGLU.so.1  libssl.so.3  libcrypto.so.3
libXau.so.6   libXdmcp.so.6  libkeystone.so.0  libunicorn.so.2
```

`libunicorn.so.2` is only present if the binary actually links it; current builds
use the statically-linked icicle emulator and will not bundle unicorn.

The following are **deliberately not bundled** and must come from the host: the
C/C++ runtime (`libc`, `libstdc++`, `libgcc_s`, `libm`, `libdl`), the Mesa GL
driver (`libGL`), and core X11/xcb. Bundling these breaks graphics or causes
runtime ABI mismatches.

Because the runtime is taken from the host, the AppImage requires a glibc at
least as new as the build runner's. It is built on `ubuntu-latest`, which is in
line with the project's stated **glibc 2.38+** requirement.

### Difference from the original released AppImage

The released image accidentally shipped `libicicle.a` (a ~45 MB static archive)
in `usr/lib/`. A static `.a` is linked at build time and never loaded at runtime,
so this script **does not** bundle it — dead weight, functionally identical.
The binary is also stripped by default (the released one was unstripped),
which is skippable via `STRIP=0`.
