# Architecture
This document is a guide for how ZathuraDbg supports a architecture under the hood. This may be helpful to you if you want to add a new architecture to ZathuraDbg or if you just want to understand how ZathuraDbg works.

ZathuraDbg is based on [capstone engine](https://capstone-engine.org/), [keystone engine](https://keystone-engine.org/) and [unicorn engine](https://www.unicorn-engine.org) as the primary three frameworks. The internals of ZathuraDbg rely on the consistent coordination between the three to work properly.

If you want to add an architecture to ZathuraDbg, it must be already supported by capstone, keystone and unicorn engine. Most major architectures are supported by them.

If the architecture that you want to add is not supported, you can create an issue to see if creating a custom emulator, assembler and disassembler is worth the effort. An example where creating them will be worth it is when the software is being used in an education setting with a custom flavour of assembly.

After implementing the following components, you have to make some additional changes at a few places as suggested in the [additional changes](#additional-changes) section. 

---

# Components of Architectures
Every architecture in ZathuraDbg needs to have different components which are essentially containers and callbacks which define different functions and predefined values for things that are later used by ZathuraDbg. 

# Containers 
Maps and vectors are a core in defining any architecture to support in ZathuraDbg. The following describes the signatures and the format for all the required containers.
### 1. regInfoMap
This is the most important map required for the definition of any architecture. It defines the name of each register as the key and the value as a pair of two numbers - the first number is the size of the register in bits and the second one is the corresponding register constant from the unicorn engine library. These are usually defined in the headers for the correspoding architecture in the [unicorn engine source code](https://github.com/unicorn-engine/unicorn).

#### Signature
```cpp
std::unordered_map<std::string, std::pair<size_t, int>> regInfoMap;
```

#### Example
The following is part of how it is implemented for the x86 architecture:
```cpp
std::unordered_map<std::string, std::pair<size_t, int>> x86RegInfoMap = {
	...
	{"EDX", {32, UC_X86_REG_EDX}},  
	{"EFLAGS", {32, UC_X86_REG_EFLAGS}},  
	{"EIP", {32, UC_X86_REG_EIP}},  
	{"ES", {16, UC_X86_REG_ES}},  
	{"ESI", {32, UC_X86_REG_ESI}},  
	{"ESP", {32, UC_X86_REG_ESP}},  
	{"FPSW", {16, UC_X86_REG_FPSW}},  
	{"FS", {16, UC_X86_REG_FS}},  
	{"GS", {16, UC_X86_REG_GS}},  
	{"IP", {16, UC_X86_REG_IP}},  
	{"RAX", {64, UC_X86_REG_RAX}},  
	{"RBP", {64, UC_X86_REG_RBP}},  
	{"RBX", {64, UC_X86_REG_RBX}},
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

### 3. archInstructions
This is a vector of strings which contains all the valid instructions provided by a certain architecture.

#### Signature
```cpp
std::vector<std::string> archInstructions{};
```

#### Example
This is how the x86 architecture implements it:
```cpp
td::vector<std::string> x86ArchInstructions = {"AAA", "AAD", "AAM", "AAS", "FABS", "ADC", "ADCX", "ADD", "ADDPD", "ADDPS", "ADDSD", "ADDSS", "ADDSUBPD", "ADDSUBPS", "FADD", "FIADD", "ADOX", "AESDECLAST", "AESDEC", "AESENCLAST", "AESENC", "AESIMC", ...}
```

# Callbacks
ZathuraDbg requires a few callbacks to be mandatorily set by every architecture in order to work.

These callbacks usually have the following singature:
```c
datatype name(const uc_mode mode, ...);
```

This is such because most architectures have different behaviours and requirements based on the currently selected mode. Modes in unicorn engine usually define the ISA, bit width (16, 32, 64, etc.), CPU or the preferred endianess of a certain architecture.

There are a few callbacks that are mandatorily required by ZathuraDbg in order to support an architecture.

### 1. getArchIPStr
Most architectures have a different name for instruction pointer register based on the mode of execution. For example, on x86_64, ZathuraDbg supports three modes. The 16, 32 and 64 bit mode. According to the architecture's definition, this instruction pointer is differently named for all three modes. it is "IP" for 16, "EIP" for 32 and "RIP" for 64 bit.

Having this callback allows ZathuraDbg to easily get the name of the instruction pointer based on the currently selected mode. 

#### Signature
```cpp
std::string getArchIPStr(const uc_mode mode);
```

#### Example
For example, the following is the `getArchIPStr` callback for x86 architecture:
```cpp
std::string x86IPStr(const uc_mode mode){  
  switch (mode) {  
	  case UC_MODE_16:  
           return "IP";  
	  case UC_MODE_32:  
            return "EIP";  
	  case UC_MODE_64:  
            return "RIP";  
	  default:  
            return ""; 
}
```

### 2. getArchSBPStr
Similar to instruction pointer, most architectures also have different names for their stack and base pointer based on the current mode of execution. This callback returns a pair of strings, the first of which is the stack pointer's name and second one is the base pointer's name.

#### Signature
```cpp
std::pair<std::string, std::string> getArchSBPStr(const uc_mode mode);
```

#### Example
The following is an example for how this is implemented for the x86 architecture:
```cpp
std::pair<std::string, std::string> x86SBPStr(const uc_mode mode){  
  switch (mode) {
	case UC_MODE_16:
	  return {"SP", "BP"};
	case UC_MODE_32:
	  return {"ESP", "EBP"};
	case UC_MODE_64:
	  return {"RSP", "RBP"};  
	default:
	  return {"", ""};
  }
}
```

### 3. isRegisterValid
This callback is needed to check whether a register is valid or not for a specific mode for an architecture. It simply returns a boolen value based on the provided mode and name.

#### Signature
```cpp
bool isRegisterValid(const std::string& regName, uc_mode mode);
```

This is where things can get a bit more complex, since there are a ton of registers for most architectures and their existence and usage is dependent on the mode of execution. 

#### Example
The following is part of the implementation of this function for x86:
```cpp
bool x86IsRegisterValid(const std::string & reg, const uc_mode mode) {
  std::string registerName = reg;
  if (registerName.contains("[") && registerName.contains(":") && registerName.contains("]")) {
	registerName = registerName.substr(0, registerName.find_first_of('['));
  }
	
  if (!x86RegInfoMap.contains(registerName)) {
	return false;
  }

  switch (mode) {
    case UC_MODE_16: {
	  if (x86RegInfoMap[registerName].first == 16) {
	    return true;
	  }

	  if (x86RegInfoMap[registerName].first > 16) {
		return false;
	  }
	  
	  break;
    }	
	...
    return true;
}
```

### 4. modeModifyCallback
This callback exists to make changes to the default arrays and maps when a change in modes is detected. This will be better understood by looking at the example given below.

#### Signature
```cpp
void modeUpdateCallback(uc_mode mode);
```

#### Example
The following is the implementation of this function for x86:
```cpp
void x86ModeUpdateCallback(const uc_mode mode){  
  switch (mode) {  
    case UC_MODE_16:  
	  x86DefaultShownRegs = x86DefaultShownRegs16;  
	  break;  
	case UC_MODE_32:  
	  x86DefaultShownRegs = x86DefaultShownRegs32;  
	  break;  
	case UC_MODE_64:  
	  x86DefaultShownRegs = x86DefaultShownRegs64;  
	  break;  
	default:
	  break;
  }
}
```


# Additional changes
After writing code for all the required components, you can proceed to make the following additional changes.

## Menubar
The [menuBar.cpp](https://github.com/ZathuraDbg/ZathuraDbg/blob/master/src/app/menuBar.cpp) contains several things that need to be updated when a new architecture is added.

You can see a few definitions at the top of the file. Every architecture needs to have these definitions.
```cpp
const char* architectureStrings[] = {"Intel x86", "ARM", "RISC-V", "PowerPC"};
const cs_arch csArchs[]    = {CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_RISCV, CS_ARCH_PPC};
```

First of all, the name of your architecture as a string should exist in the `architectureStrings` array.
After that, the architecture constant of your architecture should be at the same index in the `csArchs` array.

Next, you have to define three variables for your architecture.
- 1. String array of all the names you want to use for different modes for your architecture, in increasing order, if that is relevant. 
- 2. An array of unicorn engine constants for these modes.
- 3. An array of keystone engine constants for these modes.
- 4. An array of capstone engine constants for these modes.

The following is an example of how this is done for the x86 architecture:

```cpp
const char* x86ModeStr[] = {"16 bit", "32 bit", "64 bit"};
const uc_mode x86UCModes[] = {UC_MODE_16, UC_MODE_32, UC_MODE_64};
const ks_mode x86KSModes[] = {KS_MODE_16, KS_MODE_32, KS_MODE_64};
const cs_mode x86CSModes[] = {CS_MODE_16, CS_MODE_32, CS_MODE_64};
```

**Remember to match the order of the strings and mode constants in all 4 arrays.**


## changeEmulationSettings
This is the function responsible for updating the selected architecture. It uses an internally defined enum named `arch` define [here](https://github.com/ZathuraDbg/ZathuraDbg/blob/master/src/app/windows/windows.hpp) to determine which architecture has been selected by the user.

The enum is defined like this:
```cpp
enum arch{
    x86 = 0,
    ARM,
    RISCV,
    PowerPC
};
```

It used in the `changeEmulationSettings` function like this for x86 architecture:
```cpp
if (selectedArch == arch::x86){
	ImGui::SetNextItemWidth(ImGui::CalcTextSize(x86ModeStr[selectedMode]).x * 2 + 10);
	ImGui::Combo("##Dropdown2", &selectedMode, x86ModeStr, IM_ARRAYSIZE(x86ModeStr));

	ucArch = UC_ARCH_X86;
	ksArch = KS_ARCH_X86;
	csArch = CS_ARCH_X86;
	ucMode = x86UCModes[selectedMode];
	ksMode = x86KSModes[selectedMode];
	csMode = x86CSModes[selectedMode];
}
```
You can copy paste the exact same lines in your architecture if you don't understand ImGui, just make sure to change `x86ModeStr[selectedMode]` with `yourModeStr[selectedMode]` on the first line and then replacing the `x86ModeStr` on both places with `yourModeStr` on the second line of the function.
If you're curious, the first line sets the width of the next visual item which is a dropdown for modes which are available for your architecture.

After this, you should update the `ucArch`, `ksArch`, `csArch` with the constants for your architecture from unicorn, keystone and capstone engine respectively.

On the next three lines, you can update the modes for unicorn, keystone and capstone engine by letting the `selectedMode` variable index into your arrays that you created earlier. This variable goes from `0` to `n` so there should not be a problem with indexing if you all the four arrays that you defined earlier are consistent.

The internal state will automatically be updated as soon as the user clicks "OKAY".

## Additional requirements
If you architecture requires some additional requirements which ZathuraDbg does not already follow, please [create an issue](https://github.com/ZathuraDbg/ZathuraDbg/issues).