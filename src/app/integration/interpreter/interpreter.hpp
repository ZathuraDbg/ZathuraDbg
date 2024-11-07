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
#include "../../arch/arch.hpp"
#include "../../arch/x86.hpp"
#include "../../../utils/stringHelper.hpp"
#include "errorHandler.hpp"
#include <mutex>
#include <array>

struct registerValueT{
    uint8_t charVal{};
    uint16_t twoByteVal{};
    uint32_t fourByteVal{};
    uint64_t eightByteVal{};
    float floatVal{};
    double doubleVal{};
    struct information{
        bool is128bit = false;
        bool is256bit = false;
        bool is512bit = false;
        union {
            double doubleArray[8]{};
            float floatArray[16];
        } arrays;
    } info;
};

typedef struct{
    bool out{};
    registerValueT registerValueUn;
} registerValueInfoT;

extern std::mutex execMutex;
extern std::mutex breakpointMutex;
extern bool skipBreakpoints;
extern bool runningAsContinue;
extern bool debugPaused;
extern bool runUntilHere;
extern int runUntilLine;
extern bool wasJumpAndStepOver;
extern bool stepInBypassed;
extern bool wasStepOver;
extern bool isCodeRunning;
extern bool createStack(void* unicornEngine);
extern bool runTempCode(const std::string& codeIn, uint64_t instructionCount);
extern bool debugModeEnabled;
registerValueInfoT getRegister(const std::string& name, bool useTempContext = false);
extern uc_context *tempContext;
extern bool ucInit(void* unicornEngine);
extern uc_engine *uc;
extern bool runCode(const std::string& code_in, uint64_t instructionCount);
extern void showRegs();
extern uintptr_t ENTRY_POINT_ADDRESS;
extern uintptr_t MEMORY_EDITOR_BASE; // default
extern uintptr_t MEMORY_DEFAULT_SIZE; // default
extern uintptr_t MEMORY_ALLOCATION_SIZE;
extern uintptr_t STACK_ADDRESS;
extern uintptr_t STACK_SIZE;
extern int tempBPLineNum;
extern uint64_t CODE_BUF_SIZE;
extern uc_context* context;
extern bool stepCode(size_t instructionCount = 1);
extern std::vector<uint> breakpointLines;
extern bool resetState();
extern bool continueOverBreakpoint;
extern bool stepIn;
extern bool stepOver;
extern bool stepContinue;
extern bool use32BitLanes;
extern registerValueT getRegisterValue(const std::string& regName, bool useTempContext);
extern uint64_t expectedIP;
extern int stepOverBPLineNo;
extern uint64_t codeCurrentLen;
extern int getCurrentLine();
extern bool removeBreakpoint(const int& lineNo);

#endif