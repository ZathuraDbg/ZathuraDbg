#ifndef ZATHURA_ARCH_HPP
#define ZATHURA_ARCH_HPP
#include <unicorn/unicorn.h>
#include <string>
#include "x86.hpp"
#include "arm.hpp"
#include <keystone/keystone.h>
#include <capstone/capstone.h>

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


struct codeInformationT{
    icArch archIC;
    ks_arch archKS;
    cs_arch archCS;
    uc_mode mode;
    ks_mode modeKS;
    cs_mode modeCS;
    ks_opt_value syntax;
    const char* archStr;
};

extern std::vector<std::string> icArchStr;
extern std::vector<std::string> defaultShownRegs;
extern codeInformationT codeInformation;
extern bool initArch();
extern std::string (*getArchIPStr)();
extern const char* archIPStr;
extern const char* archBPStr;
extern const char* archSPStr;
extern std::pair<std::string, std::string> (*getArchSBPStr)();
extern bool (*isRegisterValid)(const std::string&);
extern size_t regNameToConstant(const std::string &name);
extern std::unordered_map<std::string, size_t> regInfoMap;
extern void (*modeUpdateCallback)(int arch);
extern std::vector<std::string> archInstructions;
extern void onArchChange();
#endif //ZATHURA_ARCH_HPP
