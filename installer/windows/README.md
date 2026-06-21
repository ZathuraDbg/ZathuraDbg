# Windows installer

The Windows release is an [Inno Setup 6](https://jrsoftware.org/isinfo.php)
installer, built from [`zathura.iss`](zathura.iss). It is produced automatically
in CI ([`.github/workflows/windows.yml`](../../.github/workflows/windows.yml)) —
this replaces the old hand-built script that lived on one developer's `D:\`.

## Layout the installer ships

```
{app}\bin\Zathura.exe      the app + every DLL it links
{app}\assets\              fonts, ZathuraDbg.png, ZathuraIcon.ico
```

The `bin\` + `assets\` split is **load-bearing**: the app loads `..\assets`
relative to its own EXE (`src/utils/fonts.cpp`, `src/main.cpp`). Don't flatten it.

## How it fits together

1. **`stage.sh`** assembles the install tree from a build. It resolves the DLLs
   the EXE actually links with `ldd` (so the list can't drift — CI showed the old
   hand-list was missing the OpenSSL DLLs `libssl-3-x64`/`libcrypto-3-x64`), plus
   any project-built DLLs in the build tree, plus `assets/`. Note: the icicle
   emulator links **statically** on Windows (`libicicle.a`), so there is no
   `icicle.dll` — the old script shipped a stale one.
2. **`zathura.iss`** packages that staged tree. It is fully parameterized — no
   machine paths — via `/D` defines:
   - `MyAppVersion`     — display version (CI uses the git tag, else `VERSION`)
   - `MyAppVersionInfo` — optional numeric `x.y.z.w` for the EXE VersionInfo
   - `StagingDir`       — the tree `stage.sh` produced

## Build it locally (MSYS2 MINGW64)

```sh
# 1. build (see ../../COMPILE.md for the toolchain/deps)
cd src && cmake -G Ninja -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build
cd ..

# 2. stage the install tree
installer/windows/stage.sh src/build/Zathura.exe installer/windows/staging

# 3. compile the installer (needs Inno Setup 6 / ISCC on PATH).
#    StagingDir is resolved relative to the .iss, so "staging" == installer\windows\staging
#    regardless of where you run ISCC from.
ISCC.exe /DMyAppVersion=1.1 /DStagingDir=staging installer\windows\zathura.iss
# -> dist\ZathuraDbg-1.1-windows-x64-setup.exe
```

## Code signing

The installer is currently **unsigned**, so Windows SmartScreen shows an
"unknown publisher" prompt. When a certificate is available, uncomment the
`SignTool` lines in `zathura.iss` and add a signing step to the workflow (cert
from a repo secret). No other changes needed.

## Generating the icon

`assets/ZathuraIcon.ico` is a multi-resolution icon generated from
`assets/ZathuraDbg.png`:

```sh
magick assets/ZathuraDbg.png -background none \
  -define icon:auto-resize=256,128,64,48,32,16 assets/ZathuraIcon.ico
```
