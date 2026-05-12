#ifndef ZATHURA_INTERPRETER_HPP
#define ZATHURA_INTERPRETER_HPP

/*
 * Execution state machine
 *
 * Coordinates between the UI thread and background execution threads:
 *
 * States and synchronization:
 * - isDebugReady + debugReadyMutex + debugReadyCv:
 *   Signals that preExecutionSetup() has completed and the VM is ready to
 *   execute. Set to false before setup begins, set to true after setup
 *   completes. Step/continue actions wait on debugReadyCv before proceeding.
 *
 * - isCodeRunning:
 *   True while a step/continue/run operation is in progress on a background
 *   thread. Prevents re-entrant execution requests from the UI.
 *
 * - executionComplete:
 *   Set to true when the final instruction has been reached (end breakpoint
 *   hit). Once true, further executeCode() calls are no-ops.
 *
 * - criticalSection:
 *   Protects resetState() to prevent races between state reset and active
 *   execution.
 *
 * Typical flow:
 *   1. UI sets enableDebugMode flag
 *   2. runActions() calls startDebugging() on a background thread
 *   3. Background thread calls fileRunTask() -> preExecutionSetup() ->
 *      signals isDebugReady
 *   4. UI can now request step/continue/run actions
 *   5. Each action waits on debugReadyCv, calls executeCode(), updates UI
 *      via safeHighlightLine()
 *   6. processUIUpdates() on the main thread applies pending highlight
 *      changes
 *
 * Thread safety:
 * - All execution functions (stepCode, executeCode, runCode) run on
 *   background threads spawned by executeInBackground(). UI updates are
 *   deferred via safeHighlightLine().
 * - Breakpoint operations use breakpointMutex.
 * - VM state changes during execution use execMutex.
 */

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
#include <mutex>
#include <array>
#include <vector>
#include "icicle.h"
#include <condition_variable>
#include "../../actions/actions.hpp"
#include "../../vendor/ImGuiColorTextEdit/TextEditor.h"

#define IC_CONTEXT_SAVE_FAILED (-94)
struct registerValueT{
    uint64_t eightByteVal{};
    float floatVal{};
    double doubleVal{};
    struct information{
        bool is128bit = false;
        bool is256bit = false;
        bool is512bit = false;
        bool isFloatReg = false;
        bool isDoubleReg = false;
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
extern bool initRegistersToDefinedVals();
extern bool runCode(const std::string& codeIn, const bool& execCode);
extern uint64_t lineNoToAddress(const uint64_t& lineNo);
// bool addBreakpoint(const uint64_t& address, const bool& silent);
extern bool stoppedAtBreakpoint;
extern bool nextLineHasBreakpoint;
extern bool executeCode(Icicle* icicle, const size_t& instructionCount);
extern bool executionComplete;
extern bool addBreakpointToLine(const uint64_t& lineNo, const bool& silent = false);
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
extern bool resetState(bool reInit = true);
extern bool continueOverBreakpoint;
extern bool stepIn;
extern bool stepOver;
extern bool stepContinue;
extern bool use32BitLanes;
extern registerValueT getRegisterValue(const std::string& regName);
extern Icicle* tempIcicle;
extern VmSnapshot* tempSnapshot;
extern uint64_t expectedIP;
extern int stepOverBPLineNo;
extern uint64_t codeCurrentLen;
extern uint64_t lineNo;
extern Icicle* icicle;
extern VmSnapshot* snapshot;
extern std::stack<VmSnapshot*> vmSnapshots;
extern VmSnapshot* snapshotLast;
extern int getCurrentLine();
extern bool removeBreakpointFromLineNo(const uint64_t& lineNo);
extern bool removeBreakpoint(const uint64_t& address);
extern bool eraseTempBP;
extern bool addBreakpointBack;
extern bool isEndBreakpointSet;
extern bool runningTempCode;
extern std::vector<uint8_t> codeBuf;
extern std::mutex criticalSection;
extern bool isSilentBreakpoint(const uint64_t& lineNo);
extern std::mutex debugReadyMutex;
extern std::condition_variable debugReadyCv;
extern bool isDebugReady;
extern const std::unordered_set<std::string> vfpRegs;
extern std::unordered_set<std::string> dRegs;
extern bool skipEndStep;
// extern void printBreakpoints();
extern uint64_t addressToLineNo(const uint64_t& address);
extern void safeHighlightLine(int lineNo);

#endif