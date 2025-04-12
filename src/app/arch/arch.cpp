#include "arch.hpp"
codeInformationT codeInformation{.archIC=IC_ARCH_X86_64, .archKS = KS_ARCH_X86,  .archCS = CS_ARCH_X86, .mode=UC_MODE_64, .modeKS = KS_MODE_64,.modeCS = CS_MODE_64, .syntax = KS_OPT_SYNTAX_NASM};
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
    if (modeUpdateCallback != nullptr){
        modeUpdateCallback();
        defaultShownRegs = x86DefaultShownRegs;
    }
}

bool initArch(){
    switch (codeInformation.archIC) {
        case IC_ARCH_X86_64:
            archIPStr = "RIP";
            archBPStr = "RBP";
            archSPStr = "RSP";
            // getArchIPStr = x86IPStr;
            // getArchSBPStr = x86SBPStr;
            regInfoMap = x86RegInfoMap;
            defaultShownRegs = x86DefaultShownRegs;
            isRegisterValid = x86IsRegisterValid;
            modeUpdateCallback = x86ModeUpdateCallback;
            archInstructions = x86ArchInstructions;
            return true;
        // case UC_ARCH_ARM:
        //     getArchIPStr = armIPStr;
        //     regInfoMap = armRegInfoMap;
        //     return true;
        // case UC_ARCH_ARM64:
        //     getArchIPStr = arm64IPStr;
        //     return true;
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
