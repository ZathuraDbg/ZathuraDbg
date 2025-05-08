#include "arm.hpp"
#include "arch.hpp"
#include "../../utils/stringHelper.hpp"


std::vector<std::string> armDefaultShownRegs = {
    "PC", "SP", "LR", "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10", "R11", "R12", "CPSR"
};

// std::unordered_set<std::string> armDefaultShownRegs = {
//     // "PC"
// };

std::vector<std::string> aarch64DefaultShownRegs = {
    "PC", "SP", "LR", "X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7", "X8", "X9", "X10", "X11", "X12", 
    "X13", "X14", "X15", "X16", "X17", "X18", "X19", "X20", "X21", "X22", "X23", "X24", "X25", "X26", 
    "X27", "X28", "X29", "X30", "NZCV"
};

// ARM register info mapping with register size in bits
std::unordered_map<std::string, size_t> armRegInfoMap = {
    {"invalid", 0},
    {"cpsr", 32},
    {"d0", 64},
    {"d1", 64},
    {"d10", 64},
    {"d11", 64},
    {"d12", 64},
    {"d13", 64},
    {"d14", 64},
    {"d15", 64},
    {"d16", 64},
    {"d17", 64},
    {"d18", 64},
    {"d19", 64},
    {"d2", 64},
    {"d20", 64},
    {"d21", 64},
    {"d22", 64},
    {"d23", 64},
    {"d24", 64},
    {"d25", 64},
    {"d26", 64},
    {"d27", 64},
    {"d28", 64},
    {"d29", 64},
    {"d3", 64},
    {"d30", 64},
    {"d31", 64},
    {"d4", 64},
    {"d5", 64},
    {"d6", 64},
    {"d7", 64},
    {"d8", 64},
    {"d9", 64},
    {"lr", 32},
    {"pc", 32},
    {"q0", 128},
    {"q1", 128},
    {"q10", 128},
    {"q11", 128},
    {"q12", 128},
    {"q13", 128},
    {"q14", 128},
    {"q15", 128},
    {"q2", 128},
    {"q3", 128},
    {"q4", 128},
    {"q5", 128},
    {"q6", 128},
    {"q7", 128},
    {"q8", 128},
    {"q9", 128},
    {"r0", 32},
    {"r1", 32},
    {"r2", 32},
    {"r3", 32},
    {"r4", 32},
    {"r5", 32},
    {"r6", 32},
    {"r7", 32},
    {"r8", 32},
    {"s0", 32},
    {"s1", 32},
    {"s10", 32},
    {"s11", 32},
    {"s12", 32},
    {"s13", 32},
    {"s14", 32},
    {"s15", 32},
    {"s16", 32},
    {"s17", 32},
    {"s18", 32},
    {"s19", 32},
    {"s2", 32},
    {"s20", 32},
    {"s21", 32},
    {"s22", 32},
    {"s23", 32},
    {"s24", 32},
    {"s25", 32},
    {"s26", 32},
    {"s27", 32},
    {"s28", 32},
    {"s29", 32},
    {"s3", 32},
    {"s30", 32},
    {"s31", 32},
    {"s4", 32},
    {"s5", 32},
    {"s6", 32},
    {"s7", 32},
    {"s8", 32},
    {"s9", 32},
    {"sp", 32},
    {"spsr", 32},
};

std::unordered_map<std::string, size_t> aarch64RegInfoMap = {
    {"invalid", 0},
    {"d0", 64},
    {"d1", 64},
    {"d10", 64},
    {"d11", 64},
    {"d12", 64},
    {"d13", 64},
    {"d14", 64},
    {"d15", 64},
    {"d16", 64},
    {"d17", 64},
    {"d18", 64},
    {"d19", 64},
    {"d2", 64},
    {"d20", 64},
    {"d21", 64},
    {"d22", 64},
    {"d23", 64},
    {"d24", 64},
    {"d25", 64},
    {"d26", 64},
    {"d27", 64},
    {"d28", 64},
    {"d29", 64},
    {"d3", 64},
    {"d30", 64},
    {"d31", 64},
    {"d4", 64},
    {"d5", 64},
    {"d6", 64},
    {"d7", 64},
    {"d8", 64},
    {"d9", 64},
    {"lr", 32},
    {"nzcv", 32},
    {"q0", 128},
    {"q1", 128},
    {"q10", 128},
    {"q11", 128},
    {"q12", 128},
    {"q13", 128},
    {"q14", 128},
    {"q15", 128},
    {"q16", 128},
    {"q17", 128},
    {"q18", 128},
    {"q19", 128},
    {"q2", 128},
    {"q20", 128},
    {"q21", 128},
    {"q22", 128},
    {"q23", 128},
    {"q24", 128},
    {"q25", 128},
    {"q26", 128},
    {"q27", 128},
    {"q28", 128},
    {"q29", 128},
    {"q3", 128},
    {"q30", 128},
    {"q31", 128},
    {"q4", 128},
    {"q5", 128},
    {"q6", 128},
    {"q7", 128},
    {"q8", 128},
    {"q9", 128},
    {"s0", 32},
    {"s1", 32},
    {"s10", 32},
    {"s11", 32},
    {"s12", 32},
    {"s13", 32},
    {"s14", 32},
    {"s15", 32},
    {"s16", 32},
    {"s17", 32},
    {"s18", 32},
    {"s19", 32},
    {"s2", 32},
    {"s20", 32},
    {"s21", 32},
    {"s22", 32},
    {"s23", 32},
    {"s24", 32},
    {"s25", 32},
    {"s26", 32},
    {"s27", 32},
    {"s28", 32},
    {"s29", 32},
    {"s3", 32},
    {"s30", 32},
    {"s31", 32},
    {"s4", 32},
    {"s5", 32},
    {"s6", 32},
    {"s7", 32},
    {"s8", 32},
    {"s9", 32},
    {"sp", 32},
    {"w0", 32},
    {"w1", 32},
    {"w10", 32},
    {"w11", 32},
    {"w12", 32},
    {"w13", 32},
    {"w14", 32},
    {"w15", 32},
    {"w16", 32},
    {"w17", 32},
    {"w18", 32},
    {"w19", 32},
    {"w2", 32},
    {"w20", 32},
    {"w21", 32},
    {"w22", 32},
    {"w23", 32},
    {"w24", 32},
    {"w25", 32},
    {"w26", 32},
    {"w27", 32},
    {"w28", 32},
    {"w29", 32},
    {"w3", 32},
    {"w30", 32},
    {"w4", 32},
    {"w5", 32},
    {"w6", 32},
    {"w7", 32},
    {"w8", 32},
    {"w9", 32},
    {"wzr", 32},
    {"x0", 64},
    {"x1", 64},
    {"x10", 64},
    {"x11", 64},
    {"x12", 64},
    {"x13", 64},
    {"x14", 64},
    {"x15", 64},
    {"x16", 64},
    {"x17", 64},
    {"x18", 64},
    {"x19", 64},
    {"x2", 64},
    {"x20", 64},
    {"x21", 64},
    {"x22", 64},
    {"x23", 64},
    {"x24", 64},
    {"x25", 64},
    {"x26", 64},
    {"x27", 64},
    {"x28", 64},
    {"x3", 64},
    {"x4", 64},
    {"x5", 64},
    {"x6", 64},
    {"x7", 64},
    {"x8", 64},
    {"x9", 64},
    {"xzr", 64},
};

// Basic ARM architecture instructions
std::string armIPStr() {
    return "PC"; // For ARM 32-bit, program counter is R15 or PC
}

std::string aarch64IPStr() {
    return "PC"; // For AArch64, program counter is PC
}

std::pair<std::string, std::string> armSBPStr() {
    return {"SP", "R11"}; // Stack pointer is R13 or SP, Base pointer is R11 (FP)
}

std::pair<std::string, std::string> aarch64SBPStr() {
    return {"SP", "X29"}; // Stack pointer is SP, Base pointer is X29 (FP)
}

bool armIsRegisterValid(const std::string& reg) {
    const std::string registerName = toLowerCase(reg);
    
    // Simple validation - check if register exists in map
    if (armRegInfoMap.contains(registerName)) {
        return true;
    }

    if (registerName[0] == 's') {
        if (registerName.length() > 1) {
            int regNum = std::atoi(registerName.c_str() + 1);
            return regNum >= 0 && regNum <= 15;
        }
    }

    // General registers R0-R15
    if (registerName[0] == 'r') {
        if (registerName.length() > 1) {
            int regNum = std::atoi(registerName.c_str() + 1);
            return regNum >= 0 && regNum <= 15;
        }
    }
    
    // Special registers
    if (registerName == "pc" || registerName == "lr" || registerName == "sp" || 
        registerName == "cpsr" || registerName == "spsr") {
        return true;
    }
    
    return false;
}

bool aarch64IsRegisterValid(const std::string& reg) {
    const std::string registerName = toLowerCase(reg);
    
    // Simple validation - check if register exists in map
    if (aarch64RegInfoMap.contains(registerName)) {
        return true;
    }
    
    // X registers (X0-X30)
    if (registerName[0] == 'x') {
        if (registerName.length() > 1) {
            const int regNum = std::atoi(registerName.c_str() + 1);
            return regNum >= 0 && regNum <= 30;
        }
    }
    
    // W registers (W0-W30)
    if (registerName[0] == 'w') {
        if (registerName.length() > 1) {
            int regNum = std::atoi(registerName.c_str() + 1);
            return regNum >= 0 && regNum <= 30;
        }
    }
    
    // SIMD/FP registers validation
    if (registerName[0] == 'q' || registerName[0] == 'd' || registerName[0] == 's') {
        if (registerName.length() > 1) {
            const int regNum = std::atoi(registerName.c_str() + 1);
            return regNum >= 0 && regNum <= 31;
        }
    }
    
    // Special registers
    if (registerName == "pc" || registerName == "lr" || registerName == "sp" || 
        registerName == "xzr" || registerName == "wzr" || registerName == "fp" ||
        registerName == "nzcv" || registerName == "fpcr" || registerName == "fpsr") {
        return true;
    }
    
    return false;
}

void armModeUpdateCallback(int arch) {
    // Callback when ARM mode changes
    // Could update register views or other mode-specific settings
}

void aarch64ModeUpdateCallback() {
    // Callback when AArch64 mode changes
    // Could update register views or other mode-specific settings
}
