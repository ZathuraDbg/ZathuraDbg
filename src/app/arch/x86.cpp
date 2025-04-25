#include "x86.hpp"

#include "../../utils/stringHelper.hpp"

std::vector<std::string> x86DefaultShownRegs = {"RIP", "RSP", "RBP", "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
    "CS", "DS", "ES", "FS", "GS", "SS"};

std::unordered_map<std::string, size_t> x86RegInfoMap = {
    {"invalid", {0}},
    {"ah", {8}}, {"al", {8}}, {"ax", {16}},
    {"bh", {8}}, {"bl", {8}}, {"bp", {16}}, {"bpl", {8}}, {"bx", {16}},
    {"ch", {8}}, {"cl", {8}}, {"cs", {16}}, {"cx", {16}},
    {"dh", {8}}, {"di", {16}}, {"dil", {8}}, {"dl", {8}}, {"ds", {16}}, {"dx", {16}},
    {"eax", {32}}, {"ebp", {32}}, {"ebx", {32}}, {"ecx", {32}}, {"edi", {32}}, {"edx", {32}},
    {"eflags", {32}}, {"eip", {32}}, {"es", {16}}, {"esi", {32}}, {"esp", {32}},
    {"fpsw", {16}}, {"fs", {16}}, {"gs", {16}}, {"ip", {16}},
    {"rax", {64}}, {"rbp", {64}}, {"rbx", {64}}, {"rcx", {64}}, {"rdi", {64}}, {"rdx", {64}},
    {"rip", {64}}, {"rsi", {64}}, {"rsp", {64}},
    {"si", {16}}, {"sil", {8}}, {"sp", {16}}, {"spl", {8}}, {"ss", {16}},
    {"cr0", {64}}, {"cr1", {64}}, {"cr2", {64}}, {"cr3", {64}}, {"cr4", {64}}, {"cr8", {64}},
    {"dr0", {64}}, {"dr1", {64}}, {"dr2", {64}}, {"dr3", {64}}, {"dr4", {64}}, {"dr5", {64}}, {"dr6", {64}}, {"dr7", {64}},
    {"fp0", {80}}, {"fp1", {80}}, {"fp2", {80}}, {"fp3", {80}}, {"fp4", {80}}, {"fp5", {80}}, {"fp6", {80}}, {"fp7", {80}},
    {"k0", {64}}, {"k1", {64}}, {"k2", {64}}, {"k3", {64}}, {"k4", {64}}, {"k5", {64}}, {"k6", {64}}, {"k7", {64}},
    {"mm0", {64}}, {"mm1", {64}}, {"mm2", {64}}, {"mm3", {64}}, {"mm4", {64}}, {"mm5", {64}}, {"mm6", {64}}, {"mm7", {64}},
    {"r8", {64}}, {"r9", {64}}, {"r10", {64}}, {"r11", {64}}, {"r12", {64}}, {"r13", {64}}, {"r14", {64}}, {"r15", {64}},
    {"st0", {80}}, {"st1", {80}}, {"st2", {80}}, {"st3", {80}}, {"st4", {80}}, {"st5", {80}}, {"st6", {80}}, {"st7", {80}},
    {"xmm0", {128}}, {"xmm1", {128}}, {"xmm2", {128}}, {"xmm3", {128}}, {"xmm4", {128}}, {"xmm5", {128}}, {"xmm6", {128}}, {"xmm7", {128}},
    {"xmm8", {128}}, {"xmm9", {128}}, {"xmm10", {128}}, {"xmm11", {128}}, {"xmm12", {128}}, {"xmm13", {128}}, {"xmm14", {128}}, {"xmm15", {128}},
    {"ymm0", {256}}, {"ymm1", {256}}, {"ymm2", {256}}, {"ymm3", {256}}, {"ymm4", {256}}, {"ymm5", {256}}, {"ymm6", {256}}, {"ymm7", {256}},
    {"ymm8", {256}}, {"ymm9", {256}}, {"ymm10", {256}}, {"ymm11", {256}}, {"ymm12", {256}}, {"ymm13", {256}}, {"ymm14", {256}}, {"ymm15", {256}},
    {"zmm0", {512}}, {"zmm1", {512}}, {"zmm2", {512}}, {"zmm3", {512}}, {"zmm4", {512}}, {"zmm5", {512}}, {"zmm6", {512}}, {"zmm7", {512}},
    {"zmm8", {512}}, {"zmm9", {512}}, {"zmm10", {512}}, {"zmm11", {512}}, {"zmm12", {512}}, {"zmm13", {512}}, {"zmm14", {512}}, {"zmm15", {512}},
    {"zmm16", {512}}, {"zmm17", {512}}, {"zmm18", {512}}, {"zmm19", {512}}, {"zmm20", {512}}, {"zmm21", {512}}, {"zmm22", {512}}, {"zmm23", {512}},
    {"zmm24", {512}}, {"zmm25", {512}}, {"zmm26", {512}}, {"zmm27", {512}}, {"zmm28", {512}}, {"zmm29", {512}}, {"zmm30", {512}}, {"zmm31", {512}},
    {"r8b", {8}}, {"r9b", {8}}, {"r10b", {8}}, {"r11b", {8}}, {"r12b", {8}}, {"r13b", {8}}, {"r14b", {8}}, {"r15b", {8}},
    {"r8d", {32}}, {"r9d", {32}}, {"r10d", {32}}, {"r11d", {32}}, {"r12d", {32}}, {"r13d", {32}}, {"r14d", {32}}, {"r15d", {32}},
    {"r8w", {16}}, {"r9w", {16}}, {"r10w", {16}}, {"r11w", {16}}, {"r12w", {16}}, {"r13w", {16}}, {"r14w", {16}}, {"r15w", {16}},
    {"idtr", {80}}, {"gdtr", {80}}, {"ldtr", {16}}, {"tr", {16}},
    {"fpcw", {16}}, {"fptag", {16}}, {"msr", {64}}, {"mxcsr", {32}},
    {"fs_base", {64}}, {"gs_base", {64}},
    {"flags", {32}}, {"rflags", {64}},
    {"fip", {64}}, {"fcs", {16}}, {"fdp", {64}}, {"fds", {16}}, {"fop", {16}}
};

bool x86IsRegisterValid(const std::string& reg){
    std::string registerName = reg;
    if (registerName.contains("[") && registerName.contains(":") && registerName.contains("]")){
        registerName = registerName.substr(0, registerName.find_first_of('['));
    }

    if (!x86RegInfoMap.contains(toLowerCase(registerName))){
        return false;
    }


    if (!registerName.contains("ST") || (!registerName.contains("MM") || (!registerName.contains("XMM")) ||
        (!registerName.contains("YMM")) || (!registerName.contains("ZMM"))))
    {
        if ((registerName.starts_with("XMM") || registerName.starts_with("YMM")) && registerName.length() > 3) {
            const int suffix = atoi(registerName.substr(3).c_str());
            if (suffix > 15) {
                return false;
            }
        }
        else if (registerName.starts_with("ZMM")) {
            const int suffix = atoi(registerName.substr(3).c_str());
            if (suffix > 31) {
                return false;
            }
        }
    }

    if (x86RegInfoMap[registerName] == 64){
        return true;
    }
    if (x86RegInfoMap[registerName] == 128){
        return true;
    }

    return true;
}

void x86ModeUpdateCallback(){
    return;
}