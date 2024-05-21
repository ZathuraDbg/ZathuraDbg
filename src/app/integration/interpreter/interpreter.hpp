#ifndef ZATHURA_INTERPRETER_HPP
#define ZATHURA_INTERPRETER_HPP

#include <cstring>
#include <cstdlib>
#include <iostream>
#include <unicorn/unicorn.h>
#include <unordered_map>
#include <iomanip>
#include "../nasm/nasm.hpp"

extern uc_engine *uc;
extern int regNameToConstant(std::string name);
extern int runCode(const std::string& code_in, int instructionCount);
extern void showRegs();
extern uintptr_t ENTRY_POINT_ADDRESS;
extern uintptr_t MEMORY_ALLOCATION_SIZE;
extern uintptr_t STACK_ADDRESS;
extern uintptr_t STACK_SIZE;
extern uint64_t CODE_BUF_SIZE;
#endif