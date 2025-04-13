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
#include "icicle.h"

#define IC_CONTEXT_SAVE_FAILED (-94)
struct registerValueT{
    uint64_t eightByteVal{};
    float floatVal{};
    double doubleVal{};
    struct information{
        bool is128bit = false;
        bool is256bit = false;
        bool is512bit = false;
        union {
            double doubleArray[8];
            float floatArray[16]{};
        } arrays;
    } info;
};

typedef struct{
    bool out{};
    registerValueT registerValueUn;
} registerValueInfoT;

extern VmSnapshot* saveICSnapshot(Icicle* icicle);
extern std::mutex execMutex;
extern std::mutex breakpointMutex;
extern bool skipBreakpoints;
extern bool runningAsContinue;
extern bool debugPaused;
extern bool pauseNext;
extern bool runUntilHere;
extern int runUntilLine;
extern bool wasJumpAndStepOver;
extern bool stepInBypassed;
extern bool wasStepOver;
extern bool isCodeRunning;
extern bool createStack(Icicle* icicle);
extern bool runTempCode(const std::string& codeIn, uint64_t instructionCount);
extern bool debugModeEnabled;
registerValueInfoT getRegister(const std::string& name);
extern bool setRegisterValue(const std::string& regName, const registerValueT& value);
extern bool runCode(const std::string& code_in, uint64_t instructionCount);
extern void showRegs();
extern uintptr_t ENTRY_POINT_ADDRESS;
extern uintptr_t MEMORY_EDITOR_BASE; // default
extern uintptr_t MEMORY_DEFAULT_SIZE; // default
extern uintptr_t MEMORY_ALLOCATION_SIZE;
extern uintptr_t STACK_ADDRESS;
extern uintptr_t DEFAULT_STACK_ADDRESS;
extern bool updateStack;
extern uintptr_t STACK_SIZE;
extern int tempBPLineNum;
extern uint64_t CODE_BUF_SIZE;
extern bool stepCode(size_t instructionCount = 1);
extern std::vector<uint64_t> breakpointLines;
extern bool resetState();
extern bool continueOverBreakpoint;
extern bool stepIn;
extern bool stepOver;
extern bool stepContinue;
extern bool use32BitLanes;
extern registerValueT getRegisterValue(std::string regName);
extern Icicle* tempIcicle;
extern VmSnapshot* tempSnapshot;
extern uint64_t expectedIP;
extern int stepOverBPLineNo;
extern uint64_t codeCurrentLen;
extern Icicle* icicle;
extern VmSnapshot* snapshot;
extern int getCurrentLine();
extern bool removeBreakpoint(const int& lineNo);
extern bool eraseTempBP;
#endif