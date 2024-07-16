#include "arch.hpp"
//codeInformationT codeInformation{.arch=UC_ARCH_MAX};
codeInformationT codeInformation{.arch=UC_ARCH_X86, .mode=UC_MODE_64};
std::unordered_map<std::string, std::pair<size_t, int>> regInfoMap = {};
std::string (*getArchIPStr)(uc_mode) = nullptr;
std::string (*getArchSPStr)(uc_mode) = nullptr;

bool initArch(){
    switch (codeInformation.arch) {
        case UC_ARCH_X86:
            getArchIPStr = x86IPStr;
            getArchSPStr = x86SPStr;
            regInfoMap = x86RegInfoMap;
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

void setArchMode(uc_arch arch, uc_mode mode){
    codeInformation.arch = arch;
    codeInformation.mode = mode;
}