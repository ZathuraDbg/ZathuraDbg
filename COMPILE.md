This document is a guide for how to compile ZathuraDbg. ZathuraDbg is currently only compatible with Linux on x86_64 with experimental support for Windows. Support for other operating systems will be coming soon.

# Prerequisites
ZathuraDbg is dependent on the following frameworks, in order to compile ZathuraDbg install these frameworks:
- [Unicorn Engine](https://github.com/unicorn-engine/unicorn/blob/master/docs/COMPILE.md)
- [Keystone Engine](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE.md)
- [Capstone Engine](https://github.com/capstone-engine/capstone/blob/next/BUILDING.md)

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
- Build [capstone engine](capstone-engine.org) from instructions [here](https://github.com/capstone-engine/capstone/blob/next/BUILDING.md)

## Building the project

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
cmake .. 
make -j`nproc`
```
- Incase you get errors about missing features or dlls, compile as the above
```sh
cd ..   # you should be in the src/ directory 
rm -rf build
mkdir build
cd build
CC=gcc-14 CXX=g++-14 cmake .. 
CC=gcc-14 CXX=g++-14 make
```
- ZathuraDbg binary will now be in the `src/` folder.

### For Windows
- Open MSYS2 MINGW64

- Clone the project as per the instructions mentioned above

- Build using cmake and ninja
```
cd src
mkdir build
cd build
cmake ..
ninja -j`nproc`
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
