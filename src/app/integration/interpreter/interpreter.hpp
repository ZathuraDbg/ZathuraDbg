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
#include <array>

extern bool createStack();
extern bool debugStopped;
std::pair<bool, uint64_t> getRegister(const std::string& name);
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
extern bool stepCode(size_t instructionCount = 1);
extern std::vector<int> breakpointLines;
extern bool resetState();
extern bool continueOverBreakpoint;
extern std::string toLowerCase(const std::string& input);
extern std::string toUpperCase(const std::string& input);
extern uint64_t codeCurrentLen;
extern int getCurrentLine();

#endif