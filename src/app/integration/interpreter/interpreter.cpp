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
bool use32BitLanes = false;

std::vector<uint> breakpointLines = {};

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

    const auto lineNumber= addressLineNoMap[std::to_string(instructionPointer)];
    if (!lineNumber.empty()){
        return std::atoi(lineNumber.c_str());
    }

    return -1;
}

bool removeBreakpoint(const int& lineNo) {
    breakpointMutex.lock();

    bool success = false;
    const auto it = std::ranges::find(breakpointLines, lineNo);
    if  (it != breakpointLines.end()) {
        breakpointLines.erase(it);
        success = true;
    }

    breakpointMutex.unlock();
    return success;
}

std::pair<float, float> convert64BitToTwoFloats(const uint64_t bits) {
    float lower_float, upper_float;

    const auto lowerBits = static_cast<uint32_t>(bits & 0xFFFFFFFF);
    const auto upperBits = static_cast<uint32_t>((bits >> 32) & 0xFFFFFFFF);

    std::memcpy(&lower_float, &lowerBits, sizeof(float));
    std::memcpy(&upper_float, &upperBits, sizeof(float));

    return std::make_pair(lower_float, upper_float);
}

double convert128BitToDouble(uint64_t low_bits, const uint64_t high_bits) {
    double result;
    std::memcpy(&result, &high_bits, sizeof(double));
    return result;
}

registerValueT getRegisterValue(const std::string& regName, bool useTempContext){
    auto registerInfo = regInfoMap[toUpperCase(regName)];
    auto [size, constant] = registerInfo;

    if (size == 8) {
        uint8_t valTemp8;
        useTempContext ? uc_context_reg_read(tempContext, constant, &valTemp8) : uc_context_reg_read(context, constant, &valTemp8);
        return {.charVal = valTemp8};
    }
    else if (size == 16) {
        uint16_t valTemp16;
        useTempContext ? uc_context_reg_read(tempContext, constant, &valTemp16) : uc_context_reg_read(context, constant, &valTemp16);
        return {.twoByteVal = valTemp16};
    }
    else if (size == 32) {
        uint32_t valTemp32;
        useTempContext ? uc_context_reg_read(tempContext, constant, &valTemp32) : uc_context_reg_read(context, constant, &valTemp32);
        return {.fourByteVal = valTemp32};
    }
    else if (size == 64) {
        uint64_t valTemp64;
        useTempContext ? uc_context_reg_read(tempContext, constant, &valTemp64) : uc_context_reg_read(context, constant, &valTemp64);
        return {.eightByteVal = valTemp64};
    }
    else if (size == 128){
        uint8_t xmmValue[16];
        useTempContext ? uc_context_reg_read(tempContext, constant, &xmmValue) : uc_context_reg_read(context, constant, &xmmValue);

        uint64_t upperHalf, lowerHalf;
        std::memcpy(&upperHalf, xmmValue, 8);
        std::memcpy(&lowerHalf, xmmValue + 8, 8);

        registerValueT regValue = {.doubleVal = (convert128BitToDouble(lowerHalf, upperHalf))};
        regValue.info.is128bit = true;
        if (use32BitLanes){
            regValue.info.arrays.floatArray[0] = convert64BitToTwoFloats(lowerHalf).first;
            regValue.info.arrays.floatArray[1] = convert64BitToTwoFloats(lowerHalf).second;
            regValue.info.arrays.floatArray[2] = convert64BitToTwoFloats(upperHalf).first;
            regValue.info.arrays.floatArray[3] = convert64BitToTwoFloats(upperHalf).second;
            for (int i = 4; i < 8; i++){
                regValue.info.arrays.floatArray[i] = 0;
            }

            for (int i = 0; i < 4; i++){
                if (regValue.info.arrays.floatArray[i] != 0){
                    regValue.doubleVal = regValue.floatVal = 1.0f;
                    break;
                }
            }
        }
        else {
//          1.0f just to make it pass the zero check test
            regValue = {.doubleVal = 0.0f};
            regValue.info.is128bit = true;
            regValue.info.arrays.doubleArray[0] = convert128BitToDouble(0, upperHalf);
            regValue.info.arrays.doubleArray[1] = convert128BitToDouble(0, lowerHalf);
            regValue.info.arrays.doubleArray[2] = regValue.info.arrays.doubleArray[3] = 0;
            if (regValue.info.arrays.doubleArray[0] != 0 || regValue.info.arrays.doubleArray[1] != 0){
                regValue.doubleVal = 1.0f;
            }
        }
        return regValue;
    }
    else if (size == 256){
        uint8_t arrSize = use32BitLanes ? 8 : 4;
        registerValueT regValue{};

        if (!use32BitLanes){
            double valueArray[arrSize];
            useTempContext ? uc_context_reg_read(tempContext, constant, &valueArray) : uc_context_reg_read(context, constant, valueArray);
            regValue = {.doubleVal = (valueArray[0])};

            regValue = {.doubleVal = 0.0f};
            regValue.info.is256bit = true;

            for (int i = 0; i < 4; i++){
                regValue.info.arrays.doubleArray[i] = valueArray[i];
            }

            for (double i : valueArray){
                if (i != 0){
                    regValue.doubleVal = 1.0f;
                    break;
                }
            }
        }
        else{
            float valueArray[arrSize];
            useTempContext ? uc_context_reg_read(tempContext, constant, &valueArray) : uc_context_reg_read(context, constant, valueArray);
            regValue = {.doubleVal = (valueArray[0])};
            regValue.info.is256bit = true;

            for (int i = 0; i < 8; i++){
                regValue.info.arrays.floatArray[i] = valueArray[i];
            }

            for (float i : regValue.info.arrays.floatArray){
                if (i != 0){
                    regValue.doubleVal = regValue.floatVal = 1.0f;
                    break;
                }
            }
        }

        return regValue;
    }
    else if (size == 512) {
        uint8_t arrSize = use32BitLanes ? 16 : 8;
        registerValueT regValue{};

        if (!use32BitLanes){
            double valueArray[arrSize]{};
            useTempContext ? uc_context_reg_read(tempContext, constant, &valueArray) : uc_context_reg_read(context, constant, valueArray);
            regValue = {.doubleVal = 0.0f};

            for (int i = 0; i < 8; i++){
                regValue.info.arrays.doubleArray[i] = valueArray[i];
            }

            for (double i : valueArray){
                if (i != 0){
                    regValue.doubleVal = 1.0f;
                    break;
                }
            }
            regValue.info.is512bit = true;
            return regValue;
        }
        else{
            float valueArray[arrSize]{};
            useTempContext ? uc_context_reg_read(tempContext, constant, &valueArray) : uc_context_reg_read(context, constant, valueArray);
            regValue = {.doubleVal = (valueArray[0])};

            for (int i = 0; i < 16; i++){
                regValue.info.arrays.floatArray[i] = valueArray[i];
            }

            for (float i : regValue.info.arrays.floatArray){
                if (i != 0){
                    regValue.doubleVal = regValue.floatVal = 1.0f;
                    break;
                }
            }

            regValue.info.is512bit = true;
            return regValue;
        }

    }

    return {.charVal = 00};
}


bool initRegistersToDefinedVals(){
    LOG_INFO("Initialising registers to defined values...");
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

registerValueInfoT getRegister(const std::string& name, const bool useTempContext){
    registerValueInfoT res = {false, 0};
    std::string regName = name;

    if (name.contains('[') && name.contains(']') && name.contains(':')){
        regName = name.substr(0, name.find_first_of('['));
    }

    if (useTempContext){
        return {true, getRegisterValue(regName, true)};
    }


    if (!codeHasRun){
        registerValueInfoT ret = {true, 0x00};
        if (getRegisterActualSize(toUpperCase(name)) == 128) {
            ret.registerValueUn.info.is128bit = true;
        }
        else if (getRegisterActualSize(toUpperCase(name)) == 256){
            ret.registerValueUn.info.is256bit = true;
        }
        else if (getRegisterActualSize(toUpperCase(name)) == 512) {
            ret.registerValueUn.info.is512bit = true;
        }

        return ret;
    }

    const auto value = getRegisterValue(regName, false);
    res = {true, value};
    return res;
}

bool ucInit(void* unicornEngine){
    LOG_INFO("Initializing unicorn engine...");
    if (regInfoMap.empty()){
        initArch();
    }

    if (auto err = uc_open(codeInformation.archUC, codeInformation.mode, static_cast<uc_engine **>(unicornEngine))) {
        LOG_ERROR("Failed to initialise Unicorn Engine!");
        tinyfd_messageBox("ERROR!", "Could not initialize Unicorn Engine. Please check if the environment is correctly setup.", "ok", "error", 0);
        return false;
    }

    LOG_INFO("Initiation complete...");
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
bool wasJumpAndStepOver = false;
bool stepInBypassed = false;
bool jumpAfterBypass = false;
int runUntilLine = 0;
bool wasStepOver = false;
int stepOverBpLine = 0;
std::string lastLabel{};
uint lastLineNo = 0;

void hook(uc_engine *uc, const uint64_t address, const uint32_t size, void *user_data){
    std::string currentLabel{};

    int lineNumber = -1;
    std::string str = addressLineNoMap[std::to_string(address)];
    if (!str.empty()){
        lineNumber = std::atoi(str.c_str());
    }
    else{
        lineNumber = -1;
    }

    bool jumpDetected = false;
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
        }

        return;
    }


    for (auto &[label, range]: labelLineNoRange) {
        if (lineNo > range.first && (lineNo <= range.second)) {
            currentLabel = label;
            break;
        }
    }

    if (stepOver) {
        wasStepOver = true;
    }

    LOG_DEBUG("At lineNo: " << lineNumber);
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
        if (!breakpointLines.empty()) {
            breakpointLines.erase(std::find(breakpointLines.begin(), breakpointLines.end(), stepOverBPLineNo));
        }

        breakpointMutex.unlock();
        stepOverBPLineNo = -1;
        eraseTempBP = false;
    }

    if (expectedIP == 0){
        expectedIP = address;
    }

    if (lineNumber == lastInstructionLineNo){
        executionComplete = true;
    }

    uint64_t ip = getRegisterValue(getArchIPStr(codeInformation.mode), false).eightByteVal;


    if (ip != expectedIP && expectedIP != 0 && !currentLabel.empty()) {
        if (lastLineNo == labelLineNoRange[currentLabel].second && lineNumber != lastLineNo) {
            uc_emu_stop(uc);
            uc_context_save(uc, context);
        }
    }

    if (debugModeEnabled && !skipBreakpoints){
        if (ip != expectedIP && (ip > expectedIP)){
            LOG_INFO("Jump detected!");
            jumpDetected = true;
            updateRegs();

            /* The following check makes sure that the
             * step in behavior stays consistent even when
             * the step out routine is used in order to
             * fix an issue with unicorn.
           */
            if (stepInBypassed && !jumpAfterBypass) {
                jumpAfterBypass = true;
                stepInBypassed = false;
            }
            else if (jumpAfterBypass) {
                LOG_DEBUG("Program paused after a jump is recieved after stepIn bypass");
                uc_emu_stop(uc);
                jumpAfterBypass = false;
                stepInBypassed = false;
            }

            if (stepIn){
                LOG_DEBUG("Step in detected!");
                const std::string breakPointLinNo = addressLineNoMap[std::to_string(ip)];
                tempBPLineNum = std::atoi(breakPointLinNo.c_str());
                if (!breakPointLinNo.empty()){
                    breakpointMutex.lock();
                    breakpointLines.push_back(tempBPLineNum);
                    breakpointMutex.unlock();
                }
            }
            expectedIP = ip;
        }

        editor->HighlightDebugCurrentLine(lineNumber - 1);

        if (std::ranges::find(breakpointLines, lineNumber) != breakpointLines.end() && (!skipBreakpoints)){
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
            const auto it = std::ranges::find(breakpointLines, tempBPLineNum);
            if (it != breakpointLines.end()) {
                breakpointLines.erase(it);
            }
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

    if (!wasJumpAndStepOver) {
        wasJumpAndStepOver = jumpDetected && wasStepOver;
    }
    
    uc_context_save(uc, context);
    codeCurrentLen += size;
    expectedIP += size;
    lastLineNo = lineNumber;
}

bool initUC(const std::string& codeIn) {
    initRegistersToDefinedVals();
    if (codeBuf == nullptr){
        codeBuf = static_cast<uint8_t *>(malloc(CODE_BUF_SIZE));
        memset(codeBuf, 0, CODE_BUF_SIZE);
        LOG_DEBUG("Code buffer allocated!");
    }

    const auto *code = (uint8_t *)(codeIn.c_str());
    memcpy(codeBuf, code, codeIn.length());

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
    return true;
}

bool createStack(void* unicornEngine){
    LOG_INFO("Creating stack...");

    if (!ucInit(unicornEngine)){
        LOG_ERROR("Unicorn engine initilisation failed... Quitting!");
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
    const uint64_t stackBase = STACK_ADDRESS + STACK_SIZE;
    if (uc_reg_write(uc, regNameToConstant(sp), &stackBase)){
        LOG_ERROR("Failed to write the stack pointer to base pointer, quitting!!");
        return false;
    }

    if (uc_reg_write(uc, regNameToConstant(bp), &stackBase)){
        printf("Failed to write base pointer to memory, quitting!\n");
        return false;
    }

    LOG_INFO("Stack created successfully!");
    return true;
}

bool resetState(){
    LOG_INFO("Resetting state...");
    codeHasRun = false;
    stepClickedOnce = false;
    continueOverBreakpoint = false;
    debugPaused = false;
    skipBreakpoints = false;
    executionComplete = false;
    wasStepOver = false;
    wasJumpAndStepOver = false;
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
    emptyLineNumbers.clear();
    labelLineNoMapInternal.clear();
    labelLineNoRange.clear();

    labels = {};
    emptyLineNumbers = {};
    labelLineNoRange = {};
    labelLineNoMapInternal = {};

     if (getBytes(selectedFile).empty()) {
        return false;
    }

    for (const auto &key: registerValueMap | std::views::keys){
        registerValueMap[key] = "0x00";
    }

    if (!createStack(&uc)){
        LOG_ERROR("Unable to create stack!");
        return false;
    }

    LOG_DEBUG("State reset completed!");
    return true;
}

bool isCodeRunning = false;
bool skipBreakpoints = false;
bool stepCode(const size_t instructionCount){
    LOG_DEBUG("Stepping into code...");
    if (isCodeRunning || executionComplete){
        return true;
    }

    uint64_t ip = getRegisterValue(getArchIPStr(codeInformation.mode), false).eightByteVal;

    execMutex.lock();
    isCodeRunning = true;
    if (instructionCount == 1) {
        uc_context_save(uc, context);
        ucInit(uc);
        createStack(uc);
        initUC(getBytes(selectedFile));
        uc_context_restore(uc, context);
        skipBreakpoints = true;
    }

    const auto err = uc_emu_start(uc, ip, ENTRY_POINT_ADDRESS + CODE_BUF_SIZE, 0, instructionCount);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
               err, uc_strerror(err));
        exit(-2);
    }

    if (skipBreakpoints && instructionCount == 1) {
        skipBreakpoints = !skipBreakpoints;
    }

    isCodeRunning = false;
    execMutex.unlock();
    LOG_DEBUG("Code executed by " << instructionCount << ((instructionCount>1) ? " step" : " steps") << ".");

    if (executionComplete){
        LOG_DEBUG("Execution complete...");
        return true;
    }

    {
        uc_context_save(uc, context);
        ip = getRegisterValue(getArchIPStr(codeInformation.mode), false).eightByteVal;
        if (ip != expectedIP){
            expectedIP = ip;
        }

        const std::string str =  addressLineNoMap[std::to_string(ip)];
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

   return true;
}


bool runCode(const std::string& codeIn, uint64_t instructionCount)
{
    LOG_INFO("Running code...");
    if (!initUC(codeIn)) {
        return false;
    }

    if (instructionCount != 1 || (stepClickedOnce)){
        const uc_err err = uc_emu_start(uc, ENTRY_POINT_ADDRESS, ENTRY_POINT_ADDRESS + CODE_BUF_SIZE, 0, instructionCount);
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

        const auto val = std::atoi(line.data());
        editor->HighlightDebugCurrentLine(val - 1);
        LOG_DEBUG("Highlight from runCode");
        stepClickedOnce = true;
    }

    updateRegs();
    LOG_INFO("Ran code successfully!");
    codeHasRun = true;
    return true;
}

bool runTempCode(const std::string& codeIn, uint64_t instructionCount){
    LOG_INFO("Running " << instructionCount << " temporary instructions...");

    resetState();
    runningTempCode = true;
    runCode(codeIn, instructionCount);

    tempUC = uc;
    const auto size = uc_context_size(uc);
    tempContext = static_cast<uc_context *>(malloc(size));
    memcpy(tempContext, context, size);

    uint64_t ip;
    uc_context_reg_read(tempContext, regNameToConstant(getArchIPStr(codeInformation.mode)), &ip);
    updateRegs(true);

    return true;
}
