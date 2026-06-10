#include "interpreter.hpp"
#include "../debugState.hpp"
#include <capstone/capstone.h>
#include <algorithm>

namespace {

int sourceLineIndexForAddress(const uint64_t address)
{
    const auto lineIt = addressLineNoMap.find(address);
    return lineIt != addressLineNoMap.end() && lineIt->second > 0
        ? static_cast<int>(lineIt->second - 1)
        : -1;
}

int fallbackLastSourceLineIndex()
{
    return lastInstructionLineNo > 0 ? static_cast<int>(lastInstructionLineNo - 1) : -1;
}

bool isAtCodeEnd(const uint64_t address)
{
    const auto endAddress = codeEndAddress();
    return endAddress != 0 && address == endAddress;
}

bool currentInstructionIsCall(const uint64_t address, uint64_t& fallthroughAddress)
{
    fallthroughAddress = 0;

    const auto endAddress = codeEndAddress();
    if (icicle == nullptr || endAddress == 0 || address >= endAddress)
    {
        return false;
    }

    const auto maxRead = static_cast<size_t>(std::min<uint64_t>(16, endAddress - address));
    size_t outSize = 0;
    unsigned char* bytes = icicle_mem_read(icicle, address, maxRead, &outSize);
    if (bytes == nullptr || outSize == 0)
    {
        if (bytes != nullptr)
        {
            icicle_free_buffer(bytes, outSize);
        }
        LOG_ERROR("Unable to read current instruction for step-over.");
        return false;
    }

    csh handle = 0;
    if (cs_open(codeInformation.archCS, codeInformation.modeCS, &handle) != CS_ERR_OK)
    {
        icicle_free_buffer(bytes, outSize);
        LOG_ERROR("Unable to open Capstone for step-over instruction classification.");
        return false;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* instruction = nullptr;
    const size_t count = cs_disasm(handle, bytes, outSize, address, 1, &instruction);
    icicle_free_buffer(bytes, outSize);

    bool isCall = false;
    if (count > 0)
    {
        fallthroughAddress = instruction[0].address + instruction[0].size;
        isCall = cs_insn_group(handle, &instruction[0], CS_GRP_CALL);
    }
    else
    {
        LOG_ERROR("Unable to disassemble current instruction for step-over.");
    }

    cs_free(instruction, count);
    cs_close(&handle);
    return isCall;
}

void installStoredBreakpoints()
{
    if (icicle == nullptr)
    {
        return;
    }

    std::vector<uint64_t> resolvedAddresses;

    for (const auto lineNo : breakpointLines)
    {
        const auto address = lineNoToAddress(lineNo);
        if (address != 0 && std::ranges::find(resolvedAddresses, address) == resolvedAddresses.end())
        {
            resolvedAddresses.push_back(address);
        }
    }

    for (const auto address : breakpointAddresses)
    {
        const bool isSourceMapped = addressLineNoMap.find(address) != addressLineNoMap.end();
        if (!isSourceMapped && address != 0 && std::ranges::find(resolvedAddresses, address) == resolvedAddresses.end())
        {
            resolvedAddresses.push_back(address);
        }
    }

    breakpointAddresses = resolvedAddresses;

    for (const auto address : breakpointAddresses)
    {
        icicle_add_breakpoint(icicle, address);
    }
}

}

int getCurrentLine(){
    uint64_t instructionPointer = -1;

    if (icicle != nullptr)
    {
        instructionPointer = icicle_get_pc(icicle);
    }

    if (instructionPointer == -1){
        return -1;
    }

    const auto lineIt = addressLineNoMap.find(instructionPointer);
    return lineIt != addressLineNoMap.end() && lineIt->second ? static_cast<int>(lineIt->second) : -1;
}

int handleSyscalls(void* data, uint64_t syscall_nr, const SyscallArgs* args)
{
    if (args != nullptr)
    {
        if (syscall_nr == 1)
        {
            LOG_DEBUG("Write syscall requested!");
            size_t outSize = 0;
            auto s = icicle_mem_read(static_cast<Icicle*>(data), args->arg1, args->arg2, &outSize);
            if (!s)
            {
                LOG_ERROR("Failed to read syscall write buffer.");
                return 0;
            }

            std::string j(reinterpret_cast<const char*>(s), outSize);
            icicle_free_buffer(s, outSize);
            consoleWriteThreadSafe("stdout >> " + j + "\n");
        }
        else if (syscall_nr == 60)
        {
            LOG_DEBUG("Exit syscall requested!");
        }
    }
    return 0;
}

void instructionHook(void* userData, const uint64_t address)
{

    const auto lineIndex = sourceLineIndexForAddress(address);
    if (lineIndex >= 0)
        safeHighlightLine(lineIndex);

    if (ttdEnabled)
    {
        if (!snapshot)
        {
            snapshot = icicle_vm_snapshot(icicle);
            return;
        }

        if (vmSnapshots.empty() || vmSnapshots.top() != snapshot)
        {
            vmSnapshots.push(snapshot);
        }

        snapshot = icicle_vm_snapshot(icicle);
        if (!snapshot)
        {
            LOG_ERROR("Failed to save VM snapshot for time-travel debugging.");
        }
        return;
    }

    if (!snapshot)
    {
        snapshot = icicle_vm_snapshot(icicle);
    }
}

void stackWriteHook(void* data, uint64_t address, uint8_t size, const uint64_t valueWritten)
{
    updateStack = true;
}

static bool executeCodeCore(Icicle* icicle, const size_t& instructionCount);

bool preExecutionSetup(const std::string& codeIn)
{
    initRegistersToDefinedVals();
    const auto codeBufferSize = static_cast<size_t>(CODE_BUF_SIZE);
    if (codeIn.size() > codeBufferSize)
    {
        LOG_ERROR("Assembled code is larger than the executable buffer.");
        return false;
    }

    if (codeBuf.size() != codeBufferSize){
        codeBuf.resize(codeBufferSize);
        LOG_DEBUG("Code buffer allocated!");
    }

    std::fill(codeBuf.begin(), codeBuf.end(), 0);
    std::memcpy(codeBuf.data(), codeIn.data(), codeIn.size());

    // TODO: Add a way to make stack executable
    const auto e = icicle_mem_map(icicle, ENTRY_POINT_ADDRESS, CODE_BUF_SIZE, MemoryProtection::ExecuteReadWrite);
    if (e != 0)
    {
        LOG_ERROR("Failed to map memory for writing code!");
        return false;
    }

    auto k = icicle_mem_write(icicle, ENTRY_POINT_ADDRESS, codeBuf.data(), codeBufferSize);
    if (k != 0)
    {
        LOG_ERROR("Failed to write code into executable memory.");
        return false;
    }
    icicle_set_pc(icicle, ENTRY_POINT_ADDRESS);

    // Ensure snapshot is taken before signaling ready
    if (snapshot == nullptr)
    {
        snapshot = saveICSnapshot(icicle);
        if (snapshot == nullptr) {
             LOG_ERROR("Failed to take initial snapshot!");
        }
    }

    uint32_t instructionHookID = icicle_add_execution_hook(icicle, instructionHook, nullptr);
    uint32_t stackWriteHookID = icicle_add_mem_write_hook(icicle, stackWriteHook, nullptr, STACK_ADDRESS, STACK_ADDRESS + STACK_SIZE);
    icicle_add_syscall_hook(icicle, handleSyscalls, icicle);
    installDebugWatchpointHooks();
    installStoredBreakpoints();

    // Signal that debugging setup is complete and ready for execution
    {
        std::lock_guard<std::mutex> lk(debugReadyMutex);
        isDebugReady = true;
    }
    debugReadyCv.notify_all();
    LOG_DEBUG("Debug setup complete, signaled ready.");

    return true;
}

uint64_t lineNoToAddress(const uint64_t& lineNo)
{

    if (lineNo == 0)
        return ENTRY_POINT_ADDRESS;

    for (auto& pair : addressLineNoMap)
    {
        if (pair.second == lineNo)
            return pair.first;

    }

    return 0;
}

uint64_t codeEndAddress()
{
    return codeExecutableEndAddress;
}

bool isCodeExecutedAlready = false;
bool checkStatusUpdateState(const size_t& instructionCount, RunStatus status, const uint64_t& oldBPAddr)
{
    const uintptr_t ip = icicle_get_pc(icicle);
    LOG_INFO("Execution completed! with status code: " << status << " address: " << std::hex << ip);


    const auto lineIndex = sourceLineIndexForAddress(ip);
    if (lineIndex >= 0)
        safeHighlightLine(lineIndex);

    if (isAtCodeEnd(ip))
    {
        icicle_remove_breakpoint(icicle, ip);
        isEndBreakpointSet = false;
        executionComplete = true;
        stoppedAtBreakpoint = false;
        safeHighlightLine(fallbackLastSourceLineIndex());
        return true;
    }

    if (status == RunStatus::Breakpoint)
    {
        LOG_DEBUG("Breakpoint reached at address " << icicle_get_pc(icicle));

        const auto lineIt = addressLineNoMap.find(ip);
        const uint64_t lineNo = lineIt != addressLineNoMap.end() ? lineIt->second : 0;
        if (lineNo)
        {
            if (isSilentBreakpoint(lineNo))
            {
                icicle_remove_breakpoint(icicle, ip);
                stoppedAtBreakpoint = false;
            }
            else
            {
                nextLineHasBreakpoint = true;

                /*
                   When there is a step in request and the current instruction has a breakpoint on it
                   icicle won't allow us to just step above it
                   thus we have to use this boolean flag and function call to step above it.
                */

                // This doesn't have to be done for continues though
                if (instructionCount == 1)
                {
                    executeCodeCore(icicle, 1);
                }
            }
        }
    }
    else if (status == RunStatus::Unimplemented)
    {
        LOG_DEBUG("Unimplemented instruction at address " << icicle_get_pc(icicle));
        return false;
    }
    else if (status == RunStatus::OutOfMemory)
    {
        LOG_DEBUG("Ran out of memory at: " << icicle_get_pc(icicle));
        return false;
    }
    else if (status == UnhandledException)
    {
        LOG_DEBUG("Unhandled exception. Code :" << icicle_get_exception_code(icicle));
        return false;
    }
    else if (status == RunStatus::Halt)
    {
        executionComplete = true;
        stoppedAtBreakpoint = false;
    }

    if (addBreakpointBack)
    {
        if (oldBPAddr != 0)
        {
            icicle_add_breakpoint(icicle, oldBPAddr);
        }
    }

    instructionHook(nullptr, icicle_get_pc(icicle));
    return true;
}

static bool executeCodeCore(Icicle* icicle, const size_t& instructionCount)
{
    if (icicle == nullptr)
    {
        LOG_ERROR("Attempted to run code when icicle was not initialised!");
        return false;
    }

    if (executionComplete)
    {
        LOG_ALERT("Attempt to execute code after the code is completely executed. Ignoring.");
        return true;
    }

    RunStatus status{};
    uint64_t currentInstrAddr{};

    // "next" in context of the previous line
    if (nextLineHasBreakpoint == true)
    {
        currentInstrAddr = icicle_get_pc(icicle);
        icicle_remove_breakpoint(icicle, currentInstrAddr);
        nextLineHasBreakpoint = false;

        if (instructionCount != 1)
        {
            status = icicle_step(icicle, 1);
            addBreakpointBack = false;
            if (!checkStatusUpdateState(1, status, 0))
            {
                return false;
            }

            icicle_add_breakpoint(icicle, currentInstrAddr);
        }
        else
        {
            addBreakpointBack = true;
        }
    }

    if (instructionCount == 0)
    {
        const auto endAddress = codeEndAddress();
        if (endAddress == 0)
        {
           LOG_ERROR("Cannot add end breakpoint before code has been assembled.");
        }
        else if (!icicle_add_breakpoint(icicle, endAddress) && !isEndBreakpointSet)
        {
           LOG_ERROR("Failed to add breakpoint at the end of the assembled code. The program may end unexpectedly.");
        }
        else
        {
            isEndBreakpointSet = true;
        }

        {
            std::lock_guard<std::mutex> lk(debugReadyMutex);
            isDebugReady = false;
        }

        status = icicle_run(icicle);
        if (runUntilHere)
        {
            runUntilHere = false;
            LOG_INFO("Run until here set to false");
        }

        {
            std::lock_guard<std::mutex> lk(debugReadyMutex);
            isDebugReady = true;
        }
    }
    else
    {
       status = icicle_step(icicle, instructionCount);
    }

    return checkStatusUpdateState(instructionCount, status, currentInstrAddr);
}

bool executeCode(Icicle* icicle, const size_t& instructionCount)
{
    std::lock_guard<std::mutex> execLock(execMutex);
    return executeCodeCore(icicle, instructionCount);
}

bool stepCode(const size_t instructionCount){
    LOG_DEBUG("Stepping into code requested...");

    waitForDebugReady();
    LOG_DEBUG("Debug state confirmed ready, proceeding with step.");

    std::lock_guard<std::mutex> execLock(execMutex);

    if (isCodeRunning || executionComplete){
        LOG_DEBUG("Step request ignored: Code already running or execution complete.");
        return true;
    }

    uint64_t ip = icicle_get_pc(icicle);
    isCodeRunning = true;
    if (instructionCount == 1) {
        skipBreakpoints = true;
    }

    size_t siz{};
    RunStatus status{};

    executeCodeCore(icicle, instructionCount); // This contains the core execution

    // Update state *after* execution
    ip = icicle_get_pc(icicle);
    isCodeRunning = false; // Mark as not running *after* execution

    if (executionComplete){
        const auto lineIt = addressLineNoMap.find(ip);
        const int highlightLine = lineIt != addressLineNoMap.end()
            ? static_cast<int>(lineIt->second - 1)
            : (lastInstructionLineNo > 0 ? static_cast<int>(lastInstructionLineNo - 1) : -1);
        safeHighlightLine(highlightLine);
        LOG_DEBUG("Execution complete after step.");
        return true;
    }

    {
        // If snapshot exists, free it before creating a new one
        if (snapshot)
        {
            icicle_vm_snapshot_free(snapshot);
            snapshot = nullptr;
        }
        // Save the new snapshot
        snapshot = saveICSnapshot(icicle);
        if (!snapshot) {
            LOG_ERROR("Failed to save snapshot after step.");
            return false;
        }

        ip = icicle_get_pc(icicle);
        if (ip != expectedIP){
            expectedIP = ip;
        }

        const auto lineIndex = sourceLineIndexForAddress(ip);
        if (lineIndex >= 0 && !executionComplete){
            LOG_DEBUG("Highlight from stepCode : line: " << lineIndex + 1);
            safeHighlightLine(lineIndex);
        }
        else{
             LOG_DEBUG("No line number found for current IP or execution complete.");
             return true;
        }
    }

    codeHasRun = true;

    if (skipBreakpoints){
        skipBreakpoints = !skipBreakpoints;
    }

    if (runningAsContinue) {
        runningAsContinue = !runningAsContinue;
    }

    return true;
}

bool stepOverCode()
{
    LOG_DEBUG("Semantic step-over requested...");

    waitForDebugReady();
    LOG_DEBUG("Debug state confirmed ready, proceeding with semantic step-over.");

    std::lock_guard<std::mutex> execLock(execMutex);

    if (icicle == nullptr)
    {
        LOG_ERROR("Attempted to step over code when icicle was not initialised!");
        return false;
    }

    if (isCodeRunning || executionComplete)
    {
        LOG_DEBUG("Step-over request ignored: Code already running or execution complete.");
        return true;
    }

    const uint64_t currentAddress = icicle_get_pc(icicle);
    uint64_t fallthroughAddress = 0;

    if (!currentInstructionIsCall(currentAddress, fallthroughAddress))
    {
        isCodeRunning = true;
        const bool ok = executeCodeCore(icicle, 1);
        isCodeRunning = false;
        return ok;
    }

    if (fallthroughAddress == 0)
    {
        LOG_ERROR("Current call instruction has no fallthrough address; falling back to step-in.");
        isCodeRunning = true;
        const bool ok = executeCodeCore(icicle, 1);
        isCodeRunning = false;
        return ok;
    }

    if (isAtCodeEnd(fallthroughAddress))
    {
        isCodeRunning = true;
        const bool ok = executeCodeCore(icicle, 0);
        isCodeRunning = false;
        return ok;
    }

    bool tempBreakpointAdded = false;
    {
        std::lock_guard<std::mutex> breakpointLock(breakpointMutex);
        tempBreakpointAdded = icicle_add_breakpoint(icicle, fallthroughAddress);
    }

    if (!tempBreakpointAdded)
    {
        LOG_DEBUG("Step-over fallthrough breakpoint already existed or could not be added.");
    }

    isCodeRunning = true;
    const bool ok = executeCodeCore(icicle, 0);
    isCodeRunning = false;

    if (tempBreakpointAdded)
    {
        std::lock_guard<std::mutex> breakpointLock(breakpointMutex);
        icicle_remove_breakpoint(icicle, fallthroughAddress);
    }

    if (!executionComplete)
    {
        const auto lineIndex = sourceLineIndexForAddress(icicle_get_pc(icicle));
        if (lineIndex >= 0)
        {
            safeHighlightLine(lineIndex);
        }
    }

    return ok;
}


bool runCode(const std::string& codeIn, const bool& execCode)
{
    LOG_INFO("Running code...");
    std::lock_guard<std::mutex> execLock(execMutex);

    if (!preExecutionSetup(codeIn)) {
        return false;
    }


    auto val = addressLineNoMap[ENTRY_POINT_ADDRESS];
    if (!val)
        val = 1;

    safeHighlightLine(val - 1);

    if (execCode || (stepClickedOnce)){
        if (!executeCodeCore(icicle, 0))
        {
            LOG_ERROR("Failed to run code.");
        }

        const auto lineIndex = sourceLineIndexForAddress(icicle_get_pc(icicle));
        if (lineIndex >= 0)
        {
            safeHighlightLine(lineIndex);
        }
        if (runningTempCode){
            // icicle_vm_snapshot(icicle);
            updateRegs();
        }
    }
    else {
        // Free existing snapshot before saving a new one
        if (snapshot) {
            icicle_vm_snapshot_free(snapshot);
            snapshot = nullptr;
        }
        snapshot = saveICSnapshot(icicle); // Assign the saved snapshot


        auto val = addressLineNoMap[ENTRY_POINT_ADDRESS];
        if (!val)
            val = 1;

        safeHighlightLine(val - 1);
        LOG_DEBUG("Highlight from runCode");
        stepClickedOnce = true;
    }

    codeBuf.clear();
    updateRegs();
    LOG_INFO("Ran code successfully!");
    codeHasRun = true;
    return true;
}

bool runTempCode(const std::string& codeIn, const uint64_t instructionCount){
    LOG_INFO("Running " << instructionCount << " temporary instructions...");

    resetState();
    runningTempCode = true;
    runCode(codeIn, instructionCount);

    tempIcicle = icicle;
    updateRegs(true);
    return true;
}
