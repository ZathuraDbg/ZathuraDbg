#ifndef ZATHURA_INTERPRETER_HPP
#define ZATHURA_INTERPRETER_HPP

#include <cstring>
#include <cstdlib>
#include <iostream>
#include "../../../vendor/log/clue.hpp"
#include <unicorn/unicorn.h>
#include <unordered_map>
#include <iomanip>
#include "../keystone/assembler.hpp"
#include "../../windows/windows.hpp"
#include "../../arch/x86.hpp"

extern bool createStack();
std::pair<bool, uint64_t> getRegister(std::string name);
extern bool ucInit();
extern uc_engine *uc;
extern int regNameToConstant(std::string name);
extern bool runCode(const std::string& code_in, uint64_t instructionCount);
extern void showRegs();
extern uintptr_t ENTRY_POINT_ADDRESS;
extern uintptr_t MEMORY_ALLOCATION_SIZE;
extern uintptr_t STACK_ADDRESS;
extern uintptr_t STACK_SIZE;
extern uint64_t CODE_BUF_SIZE;
extern uc_context* context;
extern bool stepCode();
extern bool resetState();
extern std::string toLowerCase(const std::string& input);
extern std::string toUpperCase(const std::string& input);
extern uint64_t codeCurrentLen;

#endif