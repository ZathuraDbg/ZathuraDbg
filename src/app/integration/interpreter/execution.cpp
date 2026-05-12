#include "interpreter.hpp"
#include <algorithm>

int getCurrentLine(){
    uint64_t instructionPointer = -1;

    if (icicle != nullptr)
    {
        instructionPointer = icicle_get_pc(icicle);
    }

    if (instructionPointer == -1){
        return -1;
    }

    const auto lineNumber = addressLineNoMap[instructionPointer];

    return (lineNumber ? lineNumber : -1);
}

int handleSyscalls(void* data, uint64_t syscall_nr, const SyscallArgs* args)
{
    if (args != nullptr)
    {
        if (syscall_nr == 1)
        {
            LOG_DEBUG("Write syscall requested!");
            size_t r;
            auto s = icicle_mem_read((Icicle*)data, args->arg1, args->arg2, &r);
            s[args->arg2] = '\0';
            std::string j(reinterpret_cast<const char*>(s));
            output.emplace_back("stdout >> " + j);
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

    const uint64_t lineNo = addressLineNoMap[address];
    if (lineNo > 0)
        safeHighlightLine(lineNo - 1);


    if (!snapshot)
    {
        snapshot = icicle_vm_snapshot(icicle);
        if (ttdEnabled)
            vmSnapshots.push(snapshot);
    }
    else
    {
        if (ttdEnabled)
        {
            if (!vmSnapshots.empty())
            {
                if (vmSnapshots.top() == snapshot)
                {
                    return;
                }
            }

            vmSnapshots.push(snapshot);
            snapshot = icicle_vm_snapshot(icicle);
        }
    }
}

void stackWriteHook(void* data, uint64_t address, uint8_t size, const uint64_t valueWritten)
{
    updateStack = true;
}

bool preExecutionSetup(const std::string& codeIn)
{
    initRegistersToDefinedVals();
    if (codeBuf.empty()){
        codeBuf.resize(CODE_BUF_SIZE);
        std::fill(codeBuf.begin(), codeBuf.end(), 0);
        LOG_DEBUG("Code buffer allocated!");
    }

    const auto *code = (uint8_t *)(codeIn.c_str());
    std::memcpy(codeBuf.data(), code, codeIn.length());

    // TODO: Add a way to make stack executable
    const auto e = icicle_mem_map(icicle, ENTRY_POINT_ADDRESS, CODE_BUF_SIZE, MemoryProtection::ExecuteReadWrite);
    if (e == -1)
    {
        LOG_ERROR("Failed to map memory for writing code!");
        return false;
    }

    auto k = icicle_mem_write(icicle, ENTRY_POINT_ADDRESS, codeBuf.data(), CODE_BUF_SIZE - 1);
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

bool isCodeExecutedAlready = false;
bool checkStatusUpdateState(const size_t& instructionCount, RunStatus status, const uint64_t& oldBPAddr)
{
    const uintptr_t ip = icicle_get_pc(icicle);
    LOG_INFO("Execution completed! with status code: " << status << " address: " << std::hex << ip);


    const uint64_t lineNo = addressLineNoMap[ip];
    if (lineNo > 0)
        safeHighlightLine(lineNo - 1);


    if (status == RunStatus::Breakpoint)
    {
        LOG_DEBUG("Breakpoint reached at address " << icicle_get_pc(icicle));

        const uint64_t lineNo = addressLineNoMap[ip];
        if (lineNo)
        {
            if (isSilentBreakpoint(lineNo))
            {
                auto s = icicle_remove_breakpoint(icicle, ip);
                if (!skipEndStep)
                {
                    status = icicle_step(icicle, 1);
                    executionComplete = true;
                    stoppedAtBreakpoint = false;
                }
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
                    executeCode(icicle, 1);
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

bool executeCode(Icicle* icicle, const size_t& instructionCount)
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
        if (!icicle_add_breakpoint(icicle, lineNoToAddress(lastInstructionLineNo)) && !isEndBreakpointSet)
        {
           LOG_ERROR("Failed to add breakpoint at the last instruction. The program may end unexpectedly.");
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
        if (!icicle_add_breakpoint(icicle, lineNoToAddress(lastInstructionLineNo)))
        {
            LOG_ERROR("Failed to add breakpoint at the last instruction. The program may end unexpectedly.");
        }

       status = icicle_step(icicle, instructionCount);
    }

    return checkStatusUpdateState(instructionCount, status, currentInstrAddr);
}

bool stepCode(const size_t instructionCount){
    LOG_DEBUG("Stepping into code requested...");

    {
        std::unique_lock<std::mutex> lk(debugReadyMutex);
        debugReadyCv.wait(lk, []{ return isDebugReady; });
    }
    LOG_DEBUG("Debug state confirmed ready, proceeding with step.");

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

    executeCode(icicle, instructionCount); // This contains the core execution

    // Update state *after* execution
    ip = icicle_get_pc(icicle);
    editor->HighlightDebugCurrentLine(addressLineNoMap[icicle_get_pc(icicle)]);
    isCodeRunning = false; // Mark as not running *after* execution

    if (executionComplete){
        editor->HighlightDebugCurrentLine(lastInstructionLineNo-1);
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

        const uint64_t lineNo =  addressLineNoMap[ip];
        if (lineNo && !executionComplete){
            LOG_DEBUG("Highlight from stepCode : line: " << lineNo);
            editor->HighlightDebugCurrentLine(lineNo - 1);
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


bool runCode(const std::string& codeIn, const bool& execCode)
{
    LOG_INFO("Running code...");
    if (!preExecutionSetup(codeIn)) {
        return false;
    }


    auto val = addressLineNoMap[ENTRY_POINT_ADDRESS];
    if (!val)
        val = 1;


    editor->HighlightDebugCurrentLine(val - 1);

    if (execCode || (stepClickedOnce)){
        if (addBreakpointToLine(lastInstructionLineNo, true))
        {
            isEndBreakpointSet = true;
        }

        if (!executeCode(icicle, 0))
        {
            LOG_ERROR("Failed to run code.");
        }

        editor->HighlightDebugCurrentLine(lastInstructionLineNo);
        if (runningTempCode){
            // icicle_vm_snapshot(icicle);
            updateRegs();
        }
    }

    codeBuf.clear();
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


        editor->HighlightDebugCurrentLine(val - 1);
        LOG_DEBUG("Highlight from runCode");
        stepClickedOnce = true;
    }

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
