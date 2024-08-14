#include "interpreter.hpp"
uintptr_t ENTRY_POINT_ADDRESS = 0x1000;
uintptr_t MEMORY_ALLOCATION_SIZE = 2 * 1024 * 1024;
uintptr_t STACK_ADDRESS = 0x300000;
uint64_t CODE_BUF_SIZE = 0x3000;
uintptr_t STACK_SIZE = 5 * 1024 * 1024;
uintptr_t MEMORY_EDITOR_BASE;
uintptr_t MEMORY_DEFAULT_SIZE = 0x2000;

uint8_t* codeBuf = nullptr;

uc_engine *uc = nullptr;
uc_context* context = nullptr;

uc_engine *tempUC = nullptr;
uc_context *tempContext = nullptr;

uint64_t codeCurrentLen = 0;
uint64_t lineNo = 1;
uint64_t expectedIP = 0;
int stepOverBPLineNo = -1;

std::mutex execMutex;
std::mutex breakpointMutex;

bool debugModeEnabled = false;
bool continueOverBreakpoint = false;
bool runningTempCode = false;
bool stepIn = false;
bool stepOver = false;
bool stepContinue = false;
bool executionComplete = false;

std::vector<int> breakpointLines = {};

int getCurrentLine(){
    uint64_t instructionPointer = -1;

    if (context != nullptr){
        uc_context_reg_read(context, regNameToConstant(getArchIPStr(codeInformation.mode)), &instructionPointer);
    }
    else if (uc != nullptr){
        uc_reg_read(uc, regNameToConstant(getArchIPStr(codeInformation.mode)), &instructionPointer);
    }

    if (instructionPointer == -1){
        return -1;
    }

    auto lineNumber= addressLineNoMap[std::to_string(instructionPointer)];
    if (!lineNumber.empty()){
        return std::atoi(lineNumber.c_str());
    }

    return -1;
}

void showRegs(){
//    LOG_DEBUG("Showing registers");
    int rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8, r9, r10, r11, r12, r13, r14, r15, rip,
        ah, al, ax, bh, bl, bx, ch, cl, cx, dh, dl, dx, si, di, bp, sp, r8d, r9d, r10d, r11d, r12d,
        r13d, r14d, r15d, r8w, r9w, r10w, r11w, r12w, r13w, r14w, r15w, r8b, r9b, r10b, r11b, r12b, r13b, r14b,
        r15b, ds, es, fs, gs, ss, eflags, fs_base, gs_base, flags, idtr, ldtr, tr, mm0, mm1, mm2, mm3, mm4, mm5, mm6,
        mm7, xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, ymm0, ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, zmm0,
        zmm1, zmm2, zmm3, zmm4,zmm5, zmm6, zmm7, cr0, cr1, cr2, cr3, cr4, cr8,
        dr0, dr1, dr2, dr3, dr4, dr5, dr6, dr7, dil, edi, sil, esi, bpl, ebp, spl, esp, cs;

    uc_reg_read(uc, UC_X86_REG_RAX, &rax);
    uc_reg_read(uc, UC_X86_REG_RBX, &rbx);
    uc_reg_read(uc, UC_X86_REG_RCX, &rcx);
    uc_reg_read(uc, UC_X86_REG_RDX, &rdx);
    uc_reg_read(uc, UC_X86_REG_RSI, &rsi);
    uc_reg_read(uc, UC_X86_REG_RDI, &rdi);
    uc_reg_read(uc, UC_X86_REG_RBP, &rbp);
    uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
    uc_reg_read(uc, UC_X86_REG_R8, &r8);
    uc_reg_read(uc, UC_X86_REG_R9, &r9);
    uc_reg_read(uc, UC_X86_REG_R10, &r10);
    uc_reg_read(uc, UC_X86_REG_R11, &r11);
    uc_reg_read(uc, UC_X86_REG_R12, &r12);
    uc_reg_read(uc, UC_X86_REG_R13, &r13);
    uc_reg_read(uc, UC_X86_REG_R14, &r14);
    uc_reg_read(uc, UC_X86_REG_R15, &r15);
    uc_reg_read(uc, UC_X86_REG_RIP, &rip);
    uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);
    uc_reg_read(uc, UC_X86_REG_CS, &cs);
    uc_reg_read(uc, UC_X86_REG_DS, &ds);
    uc_reg_read(uc, UC_X86_REG_SS, &ss);
    uc_reg_read(uc, UC_X86_REG_ES, &es);
    uc_reg_read(uc, UC_X86_REG_FS, &fs);
    uc_reg_read(uc, UC_X86_REG_GS, &gs);
    uc_reg_read(uc, UC_X86_REG_FS_BASE, &fs_base);
    uc_reg_read(uc, UC_X86_REG_GS_BASE, &gs_base);

    printf("RAX = 0x%x\t\t", rax);
    printf("RBX = 0x%x\n", rbx);
    printf("RCX = 0x%x\t\t", rcx);
    printf("RDX = 0x%x\n", rdx);
    printf("RSI = 0x%x\t\t", rsi);
    printf("RDI = 0x%x\n", rdi);
    printf("RBP = 0x%x\t\t", rbp);
    printf("RSP = 0x%x\n", rsp);
    printf("R8 = 0x%x\t\t", r8);
    printf("R9 = 0x%x\n", r9);
    printf("R10 = 0x%x\t\t", r10);
    printf("R11 = 0x%x\n", r11);
    printf("R12 = 0x%x\t\t", r12);
    printf("R13 = 0x%x\n", r13);
    printf("R14 = 0x%x\t\t", r14);
    printf("R15 = 0x%x\n", r15);
    printf("RIP = 0x%x\t\t", rip);
    printf("EFLAGS = 0x%x\n", eflags);
    printf("CS = 0x%x\t\t", cs);
    printf("SS = 0x%x\n", ss);
    printf("DS = 0x%x\t\t", ds);
    printf("FS = 0x%x\n", fs);
    printf("GS = 0x%x\t\t", ds);
    printf("FS_BASE = 0x%x\n", fs_base);
    printf("GS_BASE = 0x%x\n", gs_base);
}

uint64_t getRegisterValue(const std::string& regName, bool useTempContext){
    auto entry = regInfoMap[toUpperCase(regName)];
    auto [size, constant] = entry;
    uint64_t value{};

    if (size == 8) {
        uint8_t valTemp8;
        useTempContext ? uc_context_reg_read(tempContext, constant, &valTemp8) : uc_reg_read(uc, constant, &valTemp8);
        value = valTemp8; // force zero extension
    }
    else if (size == 16) {
        uint16_t valTemp16;
        useTempContext ? uc_context_reg_read(tempContext, constant, &valTemp16) : uc_reg_read(uc, constant, &valTemp16);
        value = valTemp16; // force zero extension
    }
    else if (size == 32) {
        uint32_t valTemp32;
        useTempContext ? uc_context_reg_read(tempContext, constant, &valTemp32) : uc_reg_read(uc, constant, &valTemp32);
        value = valTemp32; // force zero extension
    }
    else if (size == 64) {
        uint64_t valTemp64;
        useTempContext ? uc_context_reg_read(tempContext, constant, &valTemp64) : uc_reg_read(uc, constant, &valTemp64);
        value = valTemp64; // force zero extension
    }

    // 80, 128 and 512 bit unimplemented
    return value;
}

std::pair<bool, uint64_t> getRegister(const std::string& name, bool useTempContext){
    std::pair<bool, uint64_t> res = {false, 0};

    if (useTempContext){
        return {true, getRegisterValue(name, true)};
    }


    if (!codeHasRun){
        return {true, 0x00};
    }

    auto value = getRegisterValue(name, false);
    res = {true, value};
    return res;
}

bool ucInit(void* unicornEngine){
    LOG_DEBUG("Initializing unicorn engine");
    if (regInfoMap.empty()){
        initArch();
    }

    auto err = uc_open(codeInformation.archUC, codeInformation.mode, (uc_engine**)unicornEngine);
    if (err) {
        LOG_ERROR("Failed to initialise Unicorn Engine!");
        tinyfd_messageBox("ERROR!", "Could not initialize Unicorn Engine. Please check if the environment is correctly setup.", "ok", "error", 0);
        return false;
    }

    return true;
}

bool createStack(void* unicornEngine){
    LOG_DEBUG("Creating stack");

    if (!ucInit(unicornEngine)){
        return false;
    }

    uint8_t zeroBuf[STACK_SIZE];

    memset(zeroBuf, 0, STACK_SIZE);
    if (uc_mem_map(uc, STACK_ADDRESS, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)){
        LOG_ERROR("Failed to memory map the stack!!");
        return false;
    }

    if (uc_mem_write(uc, STACK_ADDRESS, zeroBuf, STACK_SIZE)) {
        LOG_ERROR("Failed to write to the stack!!");
        return false;
    }

    auto [sp, bp] = getArchSBPStr(codeInformation.mode);
    uint64_t stackBase = STACK_ADDRESS + STACK_SIZE;
    if (uc_reg_write(uc, regNameToConstant(sp), &stackBase)){
        LOG_ERROR("Failed to write the stack pointer to base pointer, quitting!!");
        return false;
    }

    if (uc_reg_write(uc, regNameToConstant(bp), &stackBase)){
        printf("Failed to write base pointer to memory, quitting!\n");
        return false;
    }

    return true;
}

bool resetState(){
    LOG_DEBUG("Resetting state!");
    codeHasRun = false;
    stepClickedOnce = false;
    continueOverBreakpoint = false;
    debugPaused = false;
    skipBreakpoints = false;
    executionComplete = false;

    codeCurrentLen = 0;
    codeFinalLen = 0;
    lineNo = 0;
    expectedIP = 0;

    assembly.clear();
    assembly.str("");
    instructionSizes.clear();
    addressLineNoMap.clear();
    editor->ClearExtraCursors();
    editor->ClearSelections();
    editor->HighlightDebugCurrentLine(-1);

    if (uc != nullptr){
        if (tempUC == uc){
            tempUC = nullptr;
        }

        uc_close(uc);
        uc = nullptr;
    }

    if (context != nullptr){
        if (tempContext == context){
            tempContext = nullptr;
        }

        uc_context_free(context);
        context = nullptr;
    }

    if (tempContext != nullptr){
        uc_context_free(tempContext);
        tempContext = nullptr;
    }

    if (tempUC != nullptr){
        uc_close(tempUC);
        tempUC = nullptr;
    }
    labels.clear();
    labelLineNoMapInternal.clear();
    labelLineNoMapInternal = {};
    labels = {};
    getBytes(selectedFile);

    for (auto& reg: registerValueMap){
        registerValueMap[reg.first] = "0x00";
    }

    if (!createStack(&uc)){
//        LOG_DEBUG("Unable to create stack!");
        return false;
    }

    return true;
}

bool isCodeRunning = false;
bool skipBreakpoints = false;
bool stepCode(size_t instructionCount){
   LOG_DEBUG("Stepping into code!");
    if (isCodeRunning || executionComplete){
        return true;
    }

    uint64_t ip;

    uc_context_restore(uc, context);
    ip = getRegisterValue(getArchIPStr(codeInformation.mode), false);

    execMutex.lock();
    isCodeRunning = true;
    auto err = uc_emu_start(uc, ip, ENTRY_POINT_ADDRESS + CODE_BUF_SIZE, 0, instructionCount);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
               err, uc_strerror(err));
    }
    isCodeRunning = false;
    execMutex.unlock();
    LOG_DEBUG("Code executed by " << instructionCount << ((instructionCount) ? "step" : "steps") << "!");

    if (executionComplete){
        return true;
    }

    {
        int lineNum;

        uc_context_save(uc, context);
        ip = getRegisterValue(getArchIPStr(codeInformation.mode), false);
        if (ip != expectedIP){
            expectedIP = ip;
        }

        std::string str =  addressLineNoMap[std::to_string(ip)];
        if (!str.empty() && (!executionComplete)){
            lineNo = std::atoi(str.c_str());
            LOG_DEBUG("Highlight from block 3 - stepCode : line: " << lineNo);
            editor->HighlightDebugCurrentLine(lineNo - 1);
        }
        else{
            return true;
        }
    }

    uc_context_save(uc, context);
    codeHasRun = true;
    if (skipBreakpoints){
        skipBreakpoints = false;
    }

   LOG_DEBUG("Code ran once!");
    return true;
}

int tempBPLineNum = -1;
bool eraseTempBP = false;

/*
 *  The current system of detecting when the execution is done is as follows:
 *  The assembling code identifies the second label in the code, and then
 *  it saves the line number of the last valid instruction.
 *  We can assume that in general, the last instruction of the first label
 *  is the last instruction of the code because the code executes from top to bottom.
 */
bool pauseNext = false;
int runUntilLine = 0;

void hook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data){
//    LOG_DEBUG("Hook called!");
    if ((!debugModeEnabled && !debugRun) || (executionComplete) || (pauseNext)){
        LOG_DEBUG("Execution halted.");
        uc_emu_stop(uc);
        uc_context_save(uc, context);
        if (executionComplete){
            editor->HighlightDebugCurrentLine(lastInstructionLineNo - 1);
        }
        if (pauseNext){
            LOG_DEBUG("Pause next detected!");
            pauseNext = false;
//            debugPaused = false;
        }
        int lineNumber;
        uint64_t ip;
        std::string str = addressLineNoMap[std::to_string(address)];
        if (!str.empty()){
            lineNumber = std::atoi(str.c_str());
        }
        return;
    }

    int lineNumber;
    uint64_t ip;
    std::string str = addressLineNoMap[std::to_string(address)];
    if (!str.empty()){
        lineNumber = std::atoi(str.c_str());
    }
    else{
        lineNumber = -1;
    }

    if (lineNumber == runUntilLine){
        LOG_DEBUG("Run until here detected!");
        LOG_DEBUG("At lineNo: " << lineNumber);
        runUntilLine = 0;
        runUntilHere = false;
        uc_emu_stop(uc);
        uc_context_save(uc, context);
    }

    if (eraseTempBP) {
//      erase the temporary breakpoint
        breakpointMutex.lock();
        LOG_DEBUG("Removing step over breakpoint line number: " << stepOverBPLineNo);
        breakpointLines.erase(std::find(breakpointLines.begin(), breakpointLines.end(), stepOverBPLineNo));
        breakpointMutex.unlock();
        stepOverBPLineNo = -1;
        eraseTempBP = false;
    }

    if (expectedIP == 0){
        expectedIP = address;
    }

    if (lineNumber == lastInstructionLineNo){
        LOG_DEBUG("At last instruction line number!");
        executionComplete = true;
    }

    if (debugModeEnabled && !skipBreakpoints){
        ip = getRegisterValue(getArchIPStr(codeInformation.mode), false);
        if (ip != expectedIP && (ip > expectedIP)){
            LOG_DEBUG("Jump detected!");
            updateRegs();
            if (stepIn){
                LOG_DEBUG("Step in detected!");
                std::string bp = addressLineNoMap[std::to_string(ip)];
                tempBPLineNum = std::atoi(bp.c_str());
                if (!bp.empty()){
                    breakpointMutex.lock();
                    breakpointLines.push_back(tempBPLineNum);
                    breakpointMutex.unlock();
                }
            }
            expectedIP = ip;
        }

        editor->HighlightDebugCurrentLine(lineNumber - 1);

        if (std::find(breakpointLines.begin(), breakpointLines.end(), lineNumber) != breakpointLines.end() && (!skipBreakpoints)){
            editor->HighlightDebugCurrentLine(lineNumber - 1);
            LOG_DEBUG("Highlight from hook - breakpoint found at lineNo " << lineNumber);
            if (!continueOverBreakpoint){
                LOG_DEBUG("Breakpoint hit!");
                uc_emu_stop(uc);
                uc_context_save(uc, context);
                continueOverBreakpoint = true;
                return;
            }
            else{
                continueOverBreakpoint = false;
            }
        }

        if (tempBPLineNum != -1){
            breakpointMutex.lock();
            breakpointLines.erase(std::find(breakpointLines.begin(), breakpointLines.end(), tempBPLineNum));
            breakpointMutex.unlock();
        }
    }
    if (stepOverBPLineNo != -1){
        eraseTempBP = true;
    }

    if (debugPaused && stepIn){
        LOG_DEBUG("Step In detected after pause!");
        stepIn = false;
        pauseNext = true;
    }

    codeCurrentLen += size;
    expectedIP += size;
}

bool initRegistersToDefinedVals(){
    uint64_t intVal;

    for(auto&[name, value]: tempRegisterValueMap){
        intVal = hexStrToInt(value);
        auto err = uc_reg_write(uc, regNameToConstant(name), &intVal);

        if (err){
            LOG_ERROR("Unable to write defined value for the register" << name);
        }
    }
    return true;
}

bool runCode(const std::string& code_in, uint64_t instructionCount)
{
    LOG_DEBUG("Running code...");
    uc_err err;
    uint8_t* code;

    initRegistersToDefinedVals();
    if (codeBuf == nullptr){
        codeBuf = (uint8_t*)malloc(CODE_BUF_SIZE);
        memset(codeBuf, 0, CODE_BUF_SIZE);
        LOG_DEBUG("Code buffer allocated!");
    }

    code = (uint8_t*)(code_in.c_str());
    memcpy(codeBuf, code, code_in.length());

    uc_mem_map(uc, ENTRY_POINT_ADDRESS, MEMORY_ALLOCATION_SIZE, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC);
    if (uc_mem_write(uc, ENTRY_POINT_ADDRESS, codeBuf, CODE_BUF_SIZE - 1)) {
        LOG_ERROR("Failed to write emulation code to memory, quit!\n");
        return false;
    }

    uc_reg_write(uc, regNameToConstant(getArchIPStr(codeInformation.mode)), &ENTRY_POINT_ADDRESS);

    if (context == nullptr){
        uc_context_alloc(uc, &context);
    }

    uc_hook trace;
    uc_hook_add(uc, &trace, UC_HOOK_CODE, (void*)hook, nullptr, 1, 0);
    if (instructionCount != 1 || (stepClickedOnce)){
        err = uc_emu_start(uc, ENTRY_POINT_ADDRESS, ENTRY_POINT_ADDRESS + CODE_BUF_SIZE, 0, instructionCount);
        if (runningTempCode){
            uc_context_save(uc, context);
            updateRegs();
        }

        if (err) {
            handleUCErrors(err);

            free(codeBuf);
            codeBuf = nullptr;
            return false;
        }
    }

    if (instructionCount != 1){
        free(codeBuf);
        codeBuf = nullptr;
    }
    else {
        uc_context_save(uc, context);

        auto line = addressLineNoMap[std::to_string(ENTRY_POINT_ADDRESS)];
        if (line.empty()){
            line = "1";
        }

        auto val = std::atoi(line.data());
        editor->HighlightDebugCurrentLine(val - 1);
        LOG_DEBUG("Highlight from runCode");
        stepClickedOnce = true;
    }

    updateRegs();
    LOG_DEBUG("Ran code successfully!");
    codeHasRun = true;
    return true;
}

bool runTempCode(const std::string& codeIn, uint64_t instructionCount){
    resetState();
    runningTempCode = true;
    runCode(codeIn, instructionCount);

    tempUC = uc;
    auto size = uc_context_size(uc);
    tempContext = static_cast<uc_context *>(malloc(size));
    memcpy(tempContext, context, size);

    uint64_t ip;
    uc_context_reg_read(tempContext, regNameToConstant(getArchIPStr(codeInformation.mode)), &ip);
    updateRegs(true);
    return true;
}