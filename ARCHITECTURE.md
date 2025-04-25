# Architecture
This document is a guide for how ZathuraDbg supports a architecture under the hood. This may be helpful to you if you want to add a new architecture to ZathuraDbg or if you just want to understand how ZathuraDbg works.

ZathuraDbg is based on [capstone engine](https://capstone-engine.org/), [keystone engine](https://keystone-engine.org/) and [icicle](https://github.com/ZathuraDbg) as the primary three frameworks. The internals of ZathuraDbg rely on the consistent coordination between the three to work properly.

If you want to add an architecture to ZathuraDbg, it must be already supported by capstone engine, keystone engine and icicle. Most major architectures are supported by them.

If the architecture that you want to add is not supported, you can create an issue to see if creating a custom emulator, assembler and disassembler is worth the effort. An example where creating them will be worth it is when the software is being used in an education setting with a custom flavour of assembly.

After implementing the following components, you have to make some additional changes at a few places as suggested in the [additional changes](#additional-changes) section. 

---

# Components of Architectures
Every architecture in ZathuraDbg needs to have different components which are essentially containers and callbacks which define different functions and predefined values for things that are later used by ZathuraDbg. 

# Containers 
Maps and vectors are a core in defining any architecture to support in ZathuraDbg. The following describes the signatures and the format for all the required containers.
### 1. regInfoMap
This is the most important map required for the definition of any architecture. It defines the name of each register as the key and the value as the size of the register.

#### Signature
```cpp
std::unordered_map<std::string, size_t> regInfoMap;
```

#### Example
The following is part of how it is implemented for the x86 architecture:
```cpp
std::unordered_map<std::string, size_t> x86RegInfoMap = {
    ...
    {"eax", {32}},
    {"ebp", {32}},
    {"ebx", {32}},
    {"ecx", {32}},
    {"edi", {32}},
    {"edx", {32}},
    {"eflags", {32}},
    {"eip", {32}},
    {"es", {16}},
    {"esi", {32}},
    {"esp", {32}},
    {"fpsw", {16}},
    {"fs", {16}},
    {"gs", {16}},
    {"ip", {16}},
    ...
}
```

### 2. defaultShownRegs
This is a simple vector which defines the registers which are shown by default by ZathuraDbg for a certain architecture and mode of execution.

#### Signature
```cpp
std::vector<std::string> defaultShownRegs{};
```

#### Example
The following is how it is defined for the x86 architecture for 64 bit mode. This vector can be changed based on the change in architecture by the user using the [modeModifyCallback](#4-modemodifycallback):
```cpp
std::vector<std::string> x86DefaultShownRegs = {"RIP", "RSP", "RBP", "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
    "CS", "DS", "ES", "FS", "GS", "SS"};
```

# Callbacks
ZathuraDbg requires a few callbacks to be mandatorily set by every architecture in order to work.

These callbacks usually have the following signature:
```c
datatype name(...);
```

This is such because most architectures have different behaviours and requirements based on the currently selected mode. Modes define the ISA or behavior of the CPU or the preferred endianess of a certain architecture.

There are a few callbacks that are mandatorily required by ZathuraDbg in order to support an architecture.

### 1. isRegisterValid
This callback is needed to check whether a register is valid or not for a specific mode for an architecture. It simply returns a boolean value based on the provided mode and name.

#### Signature
```cpp
bool isRegisterValid(const std::string& regName);
```

This is where things can get a bit more complex, since there are a ton of registers for most architectures and their existence and usage is dependent on the mode of execution. 

#### Example
The following is part of the implementation of this function for x86:
```cpp
bool x86IsRegisterValid(const std::string & reg) {
  std::string registerName = reg;
  if (registerName.contains("[") && registerName.contains(":") && registerName.contains("]")) {
	registerName = registerName.substr(0, registerName.find_first_of('['));
  }
	
  if (!x86RegInfoMap.contains(registerName)) {
	return false;
  }

  ...
  return true;
}
```

### 2. modeModifyCallback
This callback exists to make changes to the default arrays and maps when a change in modes is detected. This will be better understood by looking at the example given below.

#### Signature
```cpp
void modeUpdateCallback(int);
```

#### Example
The following is an example implementation of this function:
```cpp
void armModeUpdateCallback(int mode){  
  switch (mode) {  
    case IC_ARCH_ARM:  
	  break;  
	case IC_ARCH_THUMBV7M:  
	  break;  
	default:
	  break;
  }
}
```

# Strings
Each architecture with their respective modes should also have the following strings defined:
1. archIPStr 
2. archBPStr
3. archSPStr

These provide values for the name of the instruction pointer, base pointer and stack pointer for the given architecture respectively.

#### Example
This is how they're defined for x86_64:
```c++
archIPStr = "RIP";
archBPStr = "RBP";
archSPStr = "RSP";
```

# Additional changes
After writing code for all the required components, you can proceed to make the following additional changes.

## Menubar
The [menuBar.cpp](https://github.com/ZathuraDbg/ZathuraDbg/blob/master/src/app/menuBar.cpp) contains several things that need to be updated when a new architecture is added.

You can see a few definitions at the top of the file. Every architecture needs to have these definitions.
```cpp
const char* architectureStrings[] = {"Intel x86_64", "AArch32", "AArch64", "RISC-V", "PowerPC"};
```

First of all, the name of your architecture as a string should exist in the `architectureStrings` array.

Next, you have to define three variables for your architecture.
- 1. String array of all the names you want to use for different modes for your architecture, in increasing order, if that is relevant. 
- 2. An array of keystone engine constants for these modes.
- 3. An array of capstone engine constants for these modes.

The following is an example of how this is done for the x86 architecture:

```cpp
const char* armModeStr[] = {"ARM", "Thumb"};
const ks_mode armKSModes[] = {KS_MODE_ARM, KS_MODE_THUMB};
const cs_mode armCSModes[] = {CS_MODE_ARM, CS_MODE_THUMB};
```

**Remember to match the order of the strings and mode constants in all 3 arrays.**

## changeEmulationSettings
This is the function responsible for updating the selected architecture. It uses an internally defined enum named `arch` define [here](https://github.com/ZathuraDbg/ZathuraDbg/blob/master/src/app/windows/windows.hpp) to determine which architecture has been selected by the user.

The enum is defined like this:
```cpp
enum arch{
    x86 = 0,
    ARM,
    ARM64,
    RISCV,
    PowerPC
};
```

It used in the `changeEmulationSettings` function like this for x86 architecture:
```cpp
else if (selectedArch == arch::ARM)
{
    ... 
    if (selectedMode == 0) {
        icArch = IC_ARCH_ARM;
        ksMode = armKSModes[selectedMode];
        csMode = armCSModes[selectedMode];
        codeInformation.archStr = "arm";
    }
    else if (selectedMode == 1)
    {
        icArch = IC_ARCH_THUMBV7M;
        ksMode = armKSModes[selectedMode];
        csMode = armCSModes[selectedMode];
        codeInformation.archStr = "thumbv7m";
    }
}
```
You can copy and paste the exact same lines in your architecture if you don't understand ImGui, just make sure to change `x86ModeStr[selectedMode]` with `yourModeStr[selectedMode]` on the first line and then replacing the `x86ModeStr` on both places with `yourModeStr` on the second line of the function.
If you're curious, the first line sets the width of the next visual item which is a dropdown for modes which are available for your architecture.

After this, you should update the `icArch`, `ksArch`, `csArch` with the constants for your architecture from icicle, keystone engine and capstone engine respectively. You also have to update the `archStr`, which defines how the architecture's vm is created when you use `icicle_new`.    
These are usually just the string versions of the enum defined in `arch.hpp`.
For example, it is "aarch64", "arm", "armeb"... for the first few architectures. If yours is not above then please open an issue.
```c++
// this is not a complete list of architectures supported by icicle
typedef enum
{
    IC_ARCH_AARCH64 = 0,
    IC_ARCH_ARM,
    IC_ARCH_ARMEB,
    IC_ARCH_ARMEBV7R,
    IC_ARCH_ARMV4,
    IC_ARCH_ARMV4T,
    IC_ARCH_ARMV5TEJ,
    IC_ARCH_ARMV6,
    IC_ARCH_ARMV6M,
    IC_ARCH_ARMV7S,
    IC_ARCH_ARMV8,
    IC_ARCH_ARMV8R,
    IC_ARCH_I386,
    IC_ARCH_M68K,
    IC_ARCH_MIPS,
    IC_ARCH_MIPSEL,
    IC_ARCH_MIPSISA32R6,
    IC_ARCH_MIPSISA32R6EL,
    IC_ARCH_MSP430,
    IC_ARCH_POWERPC,
    IC_ARCH_POWERPC64,
    IC_ARCH_POWERPC64LE,
    IC_ARCH_RISCV32,
    IC_ARCH_RISCV32GC,
    IC_ARCH_RISCV32I,
    IC_ARCH_RISCV32IMC,
    IC_ARCH_RISCV64,
    IC_ARCH_RISCV64GC,
    IC_ARCH_THUMBEB,
    IC_ARCH_THUMBV4T,
    IC_ARCH_THUMBV5TE,
    IC_ARCH_THUMBV6M,
    IC_ARCH_THUMBV7M,
    IC_ARCH_THUMBV7NEON,
    IC_ARCH_X86_64,
    IC_ARCH_XTENSA
} icArch;
```

On the next three lines, you can update the modes for icicle, keystone engine and capstone engine by letting the `selectedMode` variable index into your arrays that you created earlier. This variable goes from `0` to `n` so there should not be a problem with indexing if you all the three arrays that you defined earlier are consistent.

The internal state will automatically be updated as soon as the user clicks "OKAY".

## Additional requirements
If you architecture requires some additional requirements which ZathuraDbg does not already follow, please [create an issue](https://github.com/ZathuraDbg/ZathuraDbg/issues).