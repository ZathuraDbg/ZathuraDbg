#include "arch.hpp"

#include <windows.hpp>
codeInformationT codeInformation{.archIC=IC_ARCH_X86_64, .archKS = KS_ARCH_X86,  .archCS = CS_ARCH_X86, .mode=UC_MODE_64, .modeKS = KS_MODE_64,.modeCS = CS_MODE_64, .syntax = KS_OPT_SYNTAX_NASM, .archStr = "x86_64"};
// codeInformationT codeInformation{.archIC=IC_ARCH_ARM, .archKS = KS_ARCH_ARM,  .archCS = CS_ARCH_ARM, .modeKS = KS_MODE_LITTLE_ENDIAN,.modeCS = CS_MODE_LITTLE_ENDIAN, .syntax = KS_OPT_SYNTAX_NASM, .archStr = "aarch64"};
std::unordered_map<std::string, size_t> regInfoMap = {};
std::string (*getArchIPStr)() = nullptr;
const char* archIPStr{};
const char* archBPStr{};
const char* archSPStr{};
std::pair<std::string, std::string> (*getArchSBPStr)() = nullptr;
bool (*isRegisterValid)(const std::string&) = nullptr;
void (*modeUpdateCallback)() = nullptr;
std::vector<std::string> defaultShownRegs{};
std::vector<std::string> archInstructions;

std::vector<std::string> icArchStr = {
    "aarch64", "arm", "armeb", "armebv7r", "armv4", "armv4t", "armv5tej",
    "armv6m", "armv7s", "armv8r", "i386", "m68k", "mips", "mipsel",
    "mipsisa32r6", "mipsisa32r6el", "msp430", "powerpc", "powerpc64", "powerpc64le",
    "riscv32", "riscv32gc", "riscv32i", "riscv32imc", "riscv64", "riscv64gc",
    "thumbeb", "thumbv4t", "thumbv5te", "thumbv6m", "thumbv7neon", "x86_64", "xtensa"
};

void onArchChange(){
    initArch();
    registerValueMap.clear();
    registerValueMap = {};
    tempRegisterValueMap.clear();
    tempRegisterValueMap = {};

    if (modeUpdateCallback != nullptr){
        modeUpdateCallback();
        // Set default shown registers based on architecture
        switch (codeInformation.archIC) {
            case IC_ARCH_X86_64:
                defaultShownRegs = x86DefaultShownRegs;
                break;
            case IC_ARCH_AARCH64:
                defaultShownRegs = aarch64DefaultShownRegs;
                break;
            case IC_ARCH_ARM:
            case IC_ARCH_THUMBV7M:
                defaultShownRegs = armDefaultShownRegs;
                break;
            default:
                defaultShownRegs = x86DefaultShownRegs;
                break;
        }
    }
}

bool initArch(){
    switch (codeInformation.archIC) {
        case IC_ARCH_X86_64:
            archIPStr = "RIP";
            archBPStr = "RBP";
            archSPStr = "RSP";
            regInfoMap = x86RegInfoMap;
            defaultShownRegs = x86DefaultShownRegs;
            isRegisterValid = x86IsRegisterValid;
            modeUpdateCallback = x86ModeUpdateCallback;
            archInstructions = x86ArchInstructions;
            return true;
        case IC_ARCH_AARCH64:
            archIPStr = "PC";
            archSPStr = "SP";
            archBPStr = "X29";
            regInfoMap = aarch64RegInfoMap;
            defaultShownRegs = aarch64DefaultShownRegs;
            isRegisterValid = aarch64IsRegisterValid;
            modeUpdateCallback = armModeUpdateCallback;
            archInstructions = aarch64ArchInstructions;
            return true;
        case IC_ARCH_ARM:
            archIPStr = "PC";
            archBPStr = "R11";
            archSPStr = "SP";
            regInfoMap = armRegInfoMap;
            defaultShownRegs = armDefaultShownRegs;
            isRegisterValid = armIsRegisterValid;
            modeUpdateCallback = armModeUpdateCallback;
            archInstructions = armArchInstructions;
            return true;
        case IC_ARCH_THUMBV7M:
            archIPStr = "PC";
            archBPStr = "FP";
            archSPStr = "SP";
            regInfoMap = armRegInfoMap;
            defaultShownRegs = armDefaultShownRegs;
            isRegisterValid = armIsRegisterValid;
            modeUpdateCallback = armModeUpdateCallback;
            archInstructions = armArchInstructions;
        default: ;
    }

    return false;
}


size_t regNameToConstant(const std::string &name){
    if (!regInfoMap.contains(name)){
        return regInfoMap["INVALID"];
    }

    return regInfoMap[name];
}
