This document is a guide for how to compile ZathuraDbg. ZathuraDbg is currently only compatible with Linux on x86_64 with experimental support for Windows. Support for other operating systems will be coming soon.

# Prerequisites
ZathuraDbg requires the following dependencies to be installed on your system:

## System Dependencies
- **Capstone Engine** (version 5.x) - Install from your package manager
- **Unicorn Engine** - Will be built from source automatically
- **Keystone Engine** - Will be built from source automatically

### Installing System Capstone

#### On Debian/Ubuntu
```sh
sudo apt-get install libcapstone-dev capstone-tool
```

#### On Arch Linux
```sh
sudo pacman -S capstone
```

**Note:** ZathuraDbg now uses system capstone instead of vendored capstone to ensure compatibility with your system's capstone library.

# Compilation
Install the following dependencies to start building ZathuraDbg:
### On Debian
```sh
sudo apt-get install cmake build-essential pkg-config libglfw3 libglfw3-dev nlohmann-json3-dev 
```
- If you use wayland
```sh
sudo apt-get install libglfw3-wayland

```
- Install gcc-14 and g++-14 if you don't already have it 
```sh 
sudo apt install gcc-14 g++-14
```

### On Arch Linux
```sh
sudo pacman -S base-devel cmake gcc nlohmann-json mesa
```

- If you're using wayland
```sh
sudo pacman -S glfw-wayland
```
- If you're using x11
```sh
sudo pacman -S glfw-x11
```

### On Windows

NOTE: The Windows Build has not been tested thoroughly yet so expect issues.

- Install [MSYS2](https://www.msys2.org/)
- After install it will automatically open a UCRT64 terminal window close that. Open the MSYS2 MINGW64 shortcut. Not UCRT64 nor CLANG64.
- Update the environment and then install the following dependencies
```sh
pacman -Syyu
pacman -S mingw-w64-x86_64-toolchain mingw-w64-x86_64-glfw mingw-w64-x86_64-keystone mingw-w64-x86_64-unicorn mingw-w64-x86_64-cmake git 
```
- Install capstone engine from MSYS2 packages
```sh
pacman -S mingw-w64-x86_64-capstone
```

## Building the project

**Important:** Do not use `make -j$(nproc)` on machines with many CPU cores and limited RAM. Each C++ file in this project pulls in heavy headers (ImGui, Unicorn, Capstone, etc.) and can use 1–2 GiB per compiler process. The build system caps parallel jobs from available memory automatically.

Recommended build (memory-safe, uses Ninja when available):

```sh
cd src
./build.sh
```

Or with CMake presets:

```sh
cd src
cmake --preset default
cmake --build --preset default
```

### For Linux
- Clone it with the submodules
```
git clone --recurse-submodules https://github.com/ZathuraDbg/ZathuraDbg
```
- Build using cmake
```
cd src
mkdir build
cd build
cmake -G Ninja ..
cmake --build .
```
- Incase you get errors about missing features or dlls, compile as the above
```sh
cd ..   # you should be in the src/ directory 
rm -rf build
mkdir build
cd build
CC=gcc-14 CXX=g++-14 cmake -G Ninja ..
CC=gcc-14 CXX=g++-14 cmake --build .
```
- ZathuraDbg binary will now be in the `src/` folder.

Build tuning (optional):

| CMake option | Default | Purpose |
|---|---|---|
| `OPTIMIZATION_LEVEL` | `O0` | Debug compile speed (`O0` is faster than `Og`) |
| `ZATHURA_MB_PER_JOB` | `1200` | MiB assumed per parallel compile job |
| `ZATHURA_MAX_BUILD_JOBS` | `0` (auto) | Hard cap on parallel jobs |
| `ZATHURA_LIMIT_BUILD_PARALLELISM` | `ON` | Derive job count from `/proc/meminfo` |

Install [ccache](https://ccache.dev/) for much faster rebuilds after the first compile (`pacman -S ccache` / `apt install ccache`).

### For Windows
- Open MSYS2 MINGW64

- Clone the project as per the instructions mentioned above

- Build using cmake and ninja
```
cd src
mkdir build
cd build
cmake -G Ninja ..
cmake --build .
```

- ZathuraDbg binary will now be in the `src/` folder.

- Incase you have issues relating to DLLs being missing. Copy the following DLLs from `\Whereever\msys2\is\installed\msys64\mingw64\bin` to the folder where the executable is located.
```
glfw3.dll        
libgcc_s_seh-1.dll  
libstdc++-6.dll  
libwinpthread-1.dll
libcapstone.dll  
libkeystone.dll     
libunicorn.dll
```

# Troubleshooting

## "Failed to get instruction sizes with capstone" Error

If you encounter this error when trying to run assembly code, it typically indicates one of the following issues:

### 1. Capstone Version Mismatch
ZathuraDbg requires **Capstone 5.x**. Older versions (4.x or earlier) have different architecture enum values that are incompatible.

**Check your capstone version:**
```sh
pkg-config --modversion capstone
```

If you have an older version, upgrade it:
- **Debian/Ubuntu:** Use the official capstone repository or build from source
- **Arch Linux:** `sudo pacman -Syu capstone` 

### 2. Missing Capstone Development Headers
Ensure you have the development package installed:
- **Debian/Ubuntu:** `sudo apt-get install libcapstone-dev`
- **Arch Linux:** Headers are included with the main `capstone` package

### 3. Architecture Detection Issues
If capstone returns 0 instructions when disassembling valid x86 code, the architecture constants may be mismatched between compile-time and runtime. This was a known issue with vendored capstone headers that has been fixed by using system capstone exclusively.

**Solution:** Clean and rebuild:
```sh
cd src/build
rm -rf CMakeFiles CMakeCache.txt cmake_install.cmake Makefile
cmake -G Ninja ..
cmake --build .
```

### 4. Logging
ZathuraDbg writes logs to the user-specific state/log directory at runtime:

- Linux/BSD: `$XDG_STATE_HOME/ZathuraDbg/Zathura.zlog`, or `~/.local/state/ZathuraDbg/Zathura.zlog` if `XDG_STATE_HOME` is not set.
- Windows: `%LOCALAPPDATA%\ZathuraDbg\Logs\Zathura.zlog`.
- macOS: `~/Library/Logs/ZathuraDbg/Zathura.zlog`.

Check that file for detailed error messages about which architecture capstone is using. The ImGui layout/config file is stored separately in the user config directory, such as `~/.config/ZathuraDbg/config.zlyt` on Linux.

## Build Errors

### "CS_ARCH_AARCH64 was not declared"
This error occurs when using old capstone headers. The constant was renamed to `CS_ARCH_ARM64` in capstone 5.x. The build system now uses system headers which should have the correct constants.

### Missing Dependencies
If cmake fails with "Could not find CAPSTONE", ensure:
1. Capstone is installed: `pkg-config --exists capstone && echo "found"`
2. pkg-config can find it: `pkg-config --cflags capstone`
