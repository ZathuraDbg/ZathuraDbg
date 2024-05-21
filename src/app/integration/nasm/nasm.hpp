#ifndef ZATHURA_NASM_HPP
#define ZATHURA_NASM_HPP

#include <stdlib.h>
#include "../hex/hex.hpp"
#include <iostream>
#include <fstream>
#include <algorithm>
#include <vector>

#define ASM_FILE_NAME "tmpasm.asm"

typedef enum{
    ASM_TARGET_X86 = 32,
    ASM_TARGET_X86_64 = 64,
    ASM_TARGET_INVALID = -1
} target;

extern target targetArch;

extern bool saveAsmFile(std::string assembly);
extern std::string getBytes(std::string fileName);

#endif
