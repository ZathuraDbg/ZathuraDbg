#ifndef ZATHURA_UI_ASSEMBLER_HPP
#define ZATHURA_UI_ASSEMBLER_HPP

#include <stdlib.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <vector>
#include "../../dialogs/dialogHeader.hpp"
#include "../../../vendor/keystone/include/keystone/keystone.h"
#include "../../../vendor/keystone/include/keystone/x86.h"
#include "../../../vendor/log/clue.hpp"
#include "../utils/hex/hex.hpp"

// #define ASM_FILE_NAME "tmpasm.asm"
#define ASM_FILE_NAME "/home/rc/Zathura-UI/src/test.asm"

typedef enum{
    ASM_TARGET_X86 = 32,
    ASM_TARGET_X86_64 = 64,
    ASM_TARGET_INVALID = -1
} target;


typedef struct{
    ks_arch arch;
    ks_mode mode;
    ks_opt_type optionType;
    ks_opt_value optionValue;
} keystoneSettings;

extern uint64_t totalInstructions;
extern std::map<std::string, std::string> addressLineNoMap;
extern std::vector<uint16_t> instructionSizes;
extern std::stringstream assembly;
extern bool isFirstLineLabel;
extern std::pair<std::string, std::size_t> assemble(const std::string& assemblyString, const keystoneSettings& ksSettings);
extern std::string getBytes(const std::string& fileName);
extern std::string getBytes(std::stringstream& assembly);
extern uint64_t codeFinalLen;
extern ks_engine *ks;
#endif //ZATHURA_UI_ASSEMBLER_HPP
