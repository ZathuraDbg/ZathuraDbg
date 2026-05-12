#include "interpreter.hpp"

uintptr_t ENTRY_POINT_ADDRESS = 0x10000;
uintptr_t MEMORY_ALLOCATION_SIZE = 201000;
uintptr_t DEFAULT_STACK_ADDRESS = 0x301000;
uintptr_t STACK_ADDRESS = DEFAULT_STACK_ADDRESS;
uint64_t  CODE_BUF_SIZE = 0x5000;
uintptr_t STACK_SIZE = 64 * 1024;
uintptr_t MEMORY_EDITOR_BASE;
uintptr_t MEMORY_DEFAULT_SIZE = 0x4000;

std::vector<uint8_t> codeBuf;

Icicle* icicle = nullptr;
VmSnapshot* snapshot = nullptr;
std::stack<VmSnapshot*> vmSnapshots{};
VmSnapshot* snapshotLast = nullptr;

uint64_t codeCurrentLen = 0;
uint64_t lineNo = 1;
uint64_t expectedIP = 0;
int stepOverBPLineNo = -1;

std::mutex execMutex;
std::mutex breakpointMutex;
std::mutex criticalSection{};

bool debugModeEnabled = false;
bool continueOverBreakpoint = false;
bool runningTempCode = false;
bool stepIn = false;
bool stepOver = false;
bool stepContinue = false;
bool executionComplete = false;
bool use32BitLanes = false;
bool stoppedAtBreakpoint = false;
bool nextLineHasBreakpoint = false;
bool addBreakpointBack = false;
bool skipEndStep = false;
bool isEndBreakpointSet = false;

std::vector<uint64_t> breakpointLines = {};

std::mutex debugReadyMutex;
std::condition_variable debugReadyCv;
bool isDebugReady = false;

const std::unordered_set<std::string> vfpRegs = {
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
    "s8", "s9", "s10", "s11", "s12", "s13", "s14", "s15",
    "s16", "s17", "s18", "s19", "s20", "s21", "s22", "s23",
    "s24", "s25", "s26", "s27", "s28", "s29", "s30", "s31"
};

std::unordered_set<std::string> dRegs = {
    "d0",  "d1",  "d2",  "d3",  "d4",  "d5",  "d6",  "d7",
    "d8",  "d9",  "d10", "d11", "d12", "d13", "d14", "d15",
    "d16", "d17", "d18", "d19", "d20", "d21", "d22", "d23",
    "d24", "d25", "d26", "d27", "d28", "d29", "d30", "d31"
};

int tempBPLineNum = -1;
bool eraseTempBP = false;

/*
 *  The current system of detecting when the execution is done is as follows:
 *  The assembling code identifies the second label in the code, and then
 *  it saves the line number of the last valid instruction.
 *  We can assume that in general, the last instruction of the first label
 *  is the last instruction of the code because the code executes from top to bottom.
*/

bool wasJumpAndStepOver = false;
bool stepInBypassed = false;
bool jumpAfterBypass = false;
int runUntilLine = 0;
bool wasStepOver = false;
bool pauseNext = false;
int pausedLineNo = -1;
int stepOverBpLine = 0;
std::string lastLabel{};
uint64_t lastLineNo = 0;

bool updateStack = false;

bool isCodeRunning = false;
bool skipBreakpoints = false;
bool runningAsContinue = false;

Icicle* tempIcicle = nullptr;
VmSnapshot* tempSnapshot = nullptr;
