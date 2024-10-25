# ZathuraDbg
<img width="100" src="https://i.ibb.co/wCfN9dg/a-simplistic-app-icon-illustration-of-a-mysterious-8-Nv13mot-SFSz3-GY8uhfpd-Q-yms-YVJp-JS8u-Swlx-KNK.jpg">

[![Discord](https://img.shields.io/badge/chat-on%20Discord-green.svg)](https://discord.gg/dyMuwaZfPf)

A GUI open-source assembly emulator-based debugger. Mainly for reverse engineering and learning assembly. Under development, aims to support all major architecture. Powered by Unicorn, Capstone and Keystone Engine.

ZathuraDbg is still in beta, so expect major changes in the framework used or the UI, etc.

# Screenshots
<img src="https://i.ibb.co/7SYVRZG/image.png">

<img src="https://i.ibb.co/s90gWVq/image.png">

<img src="https://i.ibb.co/Kytmwj1/image.png">

# Installation
1. Download the AppImage from the [releases](https://github.com/ZathuraDbg/ZathuraDbg) page.
2. Execute `chmod +x ZathuraDbg-*AppImage`
2. Run the program with `./ZathuraDbg-*AppImage`

# Usage
- Video Tutorial
- Text Tutorial

# Compilation
Read COMPILING.md to compile ZathuraDbg on your machine.

# Contributing
- To implement a new architecture to work with ZathuraDbg, read ARCHITECTURE.md
- For making general contributions read CONTRIBUTING.md
- If you have any questions you can always contact us or open an issue.

# Credits
- mrexodia for helping me with Unicorn related issues
- wervwolv for help with ImGui
- NSG650
- everyone else who supported this project

# FAQs
Q. Can ZathuraDbg debug binaries?    
A. No, ZathuraDbg relies solely on the assembly code with the limitations of the Unicorn Engine emulator.    
    
Q. Does ZathuraDbg support syscalls and OS level APIs?    
A. No, since Unicorn Engine is not a full OS emulator, it can't emulate system calls or OS level APIs and thus severaly limiting it's capabilities.    

Q. Which architectures are currently supported in ZathuraDbg?    
A. Intel x86 in 16, 32 and 64 bit modes.
