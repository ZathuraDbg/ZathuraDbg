#include "arch.hpp"
//codeInformationT codeInformation{.arch=UC_ARCH_MAX};
codeInformationT codeInformation{.archUC=UC_ARCH_X86, .archKS = KS_ARCH_X86, .mode=UC_MODE_64, .modeKS = KS_MODE_64};
std::unordered_map<std::string, std::pair<size_t, int>> regInfoMap = {};
std::string (*getArchIPStr)(uc_mode) = nullptr;
std::string (*getArchSPStr)(uc_mode) = nullptr;
bool (*isRegisterValid)(const std::string&, uc_mode) = nullptr;
void (*archModifyCallback)(uc_arch, uc_mode) = nullptr;
std::vector<std::string> defaultShownRegs{};

void onArchChange(){
    initArch();
    if (archModifyCallback != nullptr){
        archModifyCallback(codeInformation.archUC, codeInformation.mode);
        defaultShownRegs = x86DefaultShownRegs;
    }
}

bool initArch(){
    switch (codeInformation.archUC) {
        case UC_ARCH_X86:
            getArchIPStr = x86IPStr;
            getArchSPStr = x86SPStr;
            regInfoMap = x86RegInfoMap;
            defaultShownRegs = x86DefaultShownRegs;
            isRegisterValid = x86IsRegisterValid;
            archModifyCallback = x86ModifyCallback;
            return true;
        case UC_ARCH_ARM:
            getArchIPStr = armIPStr;
            regInfoMap = armRegInfoMap;
            return true;
        case UC_ARCH_ARM64:
            getArchIPStr = arm64IPStr;
            return true;
    }

    return false;
}


int regNameToConstant(const std::string &name){
    if (regInfoMap.find(name) == regInfoMap.end()){
        return regInfoMap["INVALID"].second;
    }

    return regInfoMap[name].second;
}
