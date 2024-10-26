This document is a guide for how to compile ZathuraDbg. ZathuraDbg is currently only compatible with Linux on x86_64 with support for other operating systems coming later.

# Prerequisites
ZathuraDbg is dependent on the following frameworks, in order to compile ZathuraDbg install these formeworks:
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
sudo pacman -S base-devel cmake gcc-14 g++-14 nlohmann-json mesa
```

- If you're using wayland
```sh
sudo pacman -S glfw-wayland
```
- If you're using x11
```sh
sudo pacman -S glfw-x11
```

## Building the project
- Clone it with the submodules
```
git clone --recurse-submodules https://github.com/ZathuraDbg/ZathuraDbg
```
- Build using cmake
```
cd src
mkdir build
cmake .. 
make
```
- Incase you get errors about missing features, compile as the above
```sh
cd ..   # you should be in the src/ directory 
rm -rf build
mkdir build
CC=gcc-14 CXX=g++-14 cmake .. 
CC=gcc-14 CXX=g++-14 make
```
- ZathuraDbg binary will now be in the `src/` folder.


