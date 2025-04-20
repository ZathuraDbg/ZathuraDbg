#include "interpreter.hpp"

#include <sys/stat.h>
uintptr_t ENTRY_POINT_ADDRESS = 0x10000;
uintptr_t MEMORY_ALLOCATION_SIZE = 201000;
uintptr_t DEFAULT_STACK_ADDRESS = 0x301000;
uintptr_t STACK_ADDRESS = DEFAULT_STACK_ADDRESS;
uint64_t  CODE_BUF_SIZE = 0x5000;
uintptr_t STACK_SIZE = 64 * 1024;
uintptr_t MEMORY_EDITOR_BASE;
uintptr_t MEMORY_DEFAULT_SIZE = 0x4000;

uint8_t* codeBuf = nullptr;

Icicle* icicle = nullptr;
VmSnapshot* snapshot = nullptr;

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

std::vector<uint64_t> breakpointLines = {};

std::mutex debugReadyMutex;
std::condition_variable debugReadyCv;
bool isDebugReady = false;

VmSnapshot* saveICSnapshot(Icicle* icicle){
    if (icicle == nullptr){
        return nullptr;
    }
    return icicle_vm_snapshot(icicle);
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

    const auto lineNumber= addressLineNoMap[std::to_string(instructionPointer)];
    if (!lineNumber.empty()){
        return std::atoi(lineNumber.c_str());
    }

    return -1;
}

bool removeBreakpoint(const uint64_t& address) {
    breakpointMutex.lock();

    bool success = false;
    if (breakpointLines.empty()) {
        breakpointMutex.unlock();
        return success;
    }

    const auto it = std::ranges::find(breakpointLines, lineNo);
    if  (it != breakpointLines.end()) {
        icicle_remove_breakpoint(icicle, address);
        breakpointLines.erase(it);
        success = true;
    }

    breakpointMutex.unlock();
    return success;
}

void printBreakpoints()
{
    size_t count;
    uint64_t *bpList = icicle_breakpoint_list(icicle, &count);
    for (size_t i = 0; i < count; i++)
    {
        LOG_INFO("Breakpoint #" << i + 1 << " at address: " << std::hex << bpList[i] << std::hex << " at line: " << (addressLineNoMap[std::to_string(bpList[i])]));
    }
}

bool removeBreakpointFromLineNo(const uint64_t& lineNo) {
    breakpointMutex.lock();
    bool success = false;

    if (isSilentBreakpoint(lineNo))
    {
        // We don't need to remove silent breakpoints
        LOG_ALERT("Attempt to remove a silent breakpoint. Ignoring.");
        return true;
    }

    if (breakpointLines.empty()) {
        breakpointMutex.unlock();
        return success;
    }

    const auto it = std::ranges::find(breakpointLines, lineNo);
    size_t size;
    const uint64_t* bpList = icicle_breakpoint_list(icicle, &size);

    if (bpList)
    {
        for (size_t i = 0; i < size; ++i) {
            if (bpList[i] == lineNoToAddress(lineNo)) {
                if  (it != breakpointLines.end()) {
                    icicle_remove_breakpoint(icicle, lineNoToAddress(lineNo));
                    breakpointLines.erase(it);
                    success = true;
                    LOG_DEBUG("Removed a breakpoint at lineNo " << lineNo);
                    editor->RemoveHighlight(lineNo);
                }
                break;
            }
        }
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

registerValueT getRegisterValue(const std::string& regName){
    const auto size = regInfoMap[regName];
    std::string lowerRegName = toLowerCase(regName);
    
    if (size <= 64) {
        uint64_t valTemp64;
        icicle_reg_read(icicle, lowerRegName.c_str(), &valTemp64);
        return {.eightByteVal = valTemp64};
    }
    if (size == 128){
        uint8_t xmmValue[16] = {0};
        size_t outSize;
        int result = icicle_reg_read_bytes(icicle, lowerRegName.c_str(), xmmValue, sizeof(xmmValue), &outSize);
        
        if (result != 0 || outSize != sizeof(xmmValue)) {
            LOG_ERROR("Failed to read register " << regName << ", result=" << result << ", outSize=" << outSize);
            return {.eightByteVal = 0};
        }

        uint64_t upperHalf, lowerHalf;
        std::memcpy(&lowerHalf, xmmValue, 8);
        std::memcpy(&upperHalf, xmmValue + 8, 8);

        registerValueT regValue = {.doubleVal = 0.0f};
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
            double val1, val2;
            std::memcpy(&val1, &lowerHalf, sizeof(double));
            std::memcpy(&val2, &upperHalf, sizeof(double));
            
            regValue.info.arrays.doubleArray[0] = val2; // Upper half
            regValue.info.arrays.doubleArray[1] = val1; // Lower half
            regValue.info.arrays.doubleArray[2] = 0;
            regValue.info.arrays.doubleArray[3] = 0;
            
            if (val1 != 0.0 || val2 != 0.0) {
                regValue.doubleVal = 1.0;
            }
        }
        return regValue;
    }
    else if (size == 256){
        uint8_t arrSize = use32BitLanes ? 8 : 4;
        registerValueT regValue{};
        uint8_t ymmValue[32] = {0};
        size_t outSize;
        
        int result = icicle_reg_read_bytes(icicle, lowerRegName.c_str(), ymmValue, sizeof(ymmValue), &outSize);
        if (result != 0 || outSize != sizeof(ymmValue)) {
            LOG_ERROR("Failed to read register " << regName << ", result=" << result << ", outSize=" << outSize);
            return {.eightByteVal = 0};
        }

        if (!use32BitLanes){
            double valueArray[arrSize] = {0};
            
            // Convert bytes to doubles
            for (int i = 0; i < 4; i++) {
                uint64_t bits;
                std::memcpy(&bits, &ymmValue[i * 8], 8);
                // Properly interpret the bits as a double
                double val;
                std::memcpy(&val, &bits, sizeof(double));
                valueArray[i] = val;
            }
            
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
            
            // Convert bytes to floats (8 floats in a 256-bit register)
            for (int i = 0; i < 8; i++) {
                uint32_t bits;
                std::memcpy(&bits, &ymmValue[i * 4], 4);
                valueArray[i] = *reinterpret_cast<float*>(&bits);
            }
            
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
        uint8_t zmmValue[64] = {0};
        size_t outSize;
        
        int result = icicle_reg_read_bytes(icicle, lowerRegName.c_str(), zmmValue, sizeof(zmmValue), &outSize);
        if (result != 0 || outSize != sizeof(zmmValue)) {
            LOG_ERROR("Failed to read register " << regName << ", result=" << result << ", outSize=" << outSize);
            return {.eightByteVal = 0};
        }

        if (!use32BitLanes){
            double valueArray[arrSize]{};
            
            // Convert bytes to doubles
            for (int i = 0; i < 8; i++) {
                uint64_t bits;
                std::memcpy(&bits, &zmmValue[i * 8], 8);
                // Properly interpret the bits as a double
                double val;
                std::memcpy(&val, &bits, sizeof(double));
                valueArray[i] = val;
            }
            
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
            
            // Convert bytes to floats (16 floats in a 512-bit register)
            for (int i = 0; i < 16; i++) {
                uint32_t bits;
                std::memcpy(&bits, &zmmValue[i * 4], 4);
                valueArray[i] = *reinterpret_cast<float*>(&bits);
            }
            
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

    return {.eightByteVal = 00};
}


bool initRegistersToDefinedVals(){
    LOG_INFO("Initialising registers to defined values...");
    uint64_t intVal;

    for(auto&[name, value]: tempRegisterValueMap){
        intVal = hexStrToInt(value);
        icicle_reg_write(icicle, toLowerCase(name).c_str(), intVal);
    }
    return true;
}

// Function to set register values, handling registers of all sizes
bool setRegisterValue(const std::string& regName, const registerValueT& value) {
    const auto size = regInfoMap[regName];
    std::string lowerRegName = toLowerCase(regName);
    
    // For registers <= 64 bits, use the standard write function
    if (size <= 64) {
        return icicle_reg_write(icicle, lowerRegName.c_str(), value.eightByteVal) == 0;
    }
    
    // For larger registers (XMM, YMM, ZMM), we need to construct a byte array
    if (size == 128) {
        uint8_t xmmValue[16] = {0};
        
        if (use32BitLanes) {
            // Handle 32-bit lanes (4 float values)
            for (int i = 0; i < 4; i++) {
                uint32_t bits;
                float fval = value.info.arrays.floatArray[i];
                std::memcpy(&bits, &fval, sizeof(float));
                
                // Write to the appropriate position in the byte array
                std::memcpy(xmmValue + (i * 4), &bits, 4);
            }
        } else {
            // Handle 64-bit lanes (2 double values)
            // Note: In getRegisterValue, we store index 0 = upper half, index 1 = lower half
            // So we need to reverse the order when writing bytes
            
            // Write lower half (index 1) to first 8 bytes
            uint64_t bits_lower;
            double dval_lower = value.info.arrays.doubleArray[1]; // Lower half is index 1
            std::memcpy(&bits_lower, &dval_lower, sizeof(double));
            std::memcpy(xmmValue, &bits_lower, 8);
            
            // Write upper half (index 0) to second 8 bytes
            uint64_t bits_upper;
            double dval_upper = value.info.arrays.doubleArray[0]; // Upper half is index 0
            std::memcpy(&bits_upper, &dval_upper, sizeof(double));
            std::memcpy(xmmValue + 8, &bits_upper, 8);
        }
        
        // Write the bytes to the register using icicle_reg_write_bytes
        int result = icicle_reg_write_bytes(icicle, lowerRegName.c_str(), xmmValue, sizeof(xmmValue));
        if (result != 0) {
            LOG_ERROR("Failed to write to XMM register " << regName << ", result=" << result);
            return false;
        }
        return true;
    }
    else if (size == 256) {
        uint8_t ymmValue[32] = {0};
        
        if (use32BitLanes) {
            // Handle 32-bit lanes (8 float values)
            for (int i = 0; i < 8; i++) {
                uint32_t bits;
                float fval = value.info.arrays.floatArray[i];
                std::memcpy(&bits, &fval, sizeof(float));
                
                // Write to the appropriate position in the byte array
                std::memcpy(ymmValue + (i * 4), &bits, 4);
            }
        } else {
            // Handle 64-bit lanes (4 double values)
            // For 256-bit registers, we need to maintain the same ordering as in getRegisterValue
            for (int i = 0; i < 4; i++) {
                uint64_t bits;
                double dval = value.info.arrays.doubleArray[i];
                std::memcpy(&bits, &dval, sizeof(double));
                
                // Write to the appropriate position in the byte array
                std::memcpy(ymmValue + (i * 8), &bits, 8);
            }
        }
        
        // Write the bytes to the register using icicle_reg_write_bytes
        int result = icicle_reg_write_bytes(icicle, lowerRegName.c_str(), ymmValue, sizeof(ymmValue));
        if (result != 0) {
            LOG_ERROR("Failed to write to YMM register " << regName << ", result=" << result);
            return false;
        }
        return true;
    }
    else if (size == 512) {
        uint8_t zmmValue[64] = {0};
        
        if (use32BitLanes) {
            // Handle 32-bit lanes (16 float values)
            for (int i = 0; i < 16; i++) {
                uint32_t bits;
                float fval = value.info.arrays.floatArray[i];
                std::memcpy(&bits, &fval, sizeof(float));
                
                // Write to the appropriate position in the byte array
                std::memcpy(zmmValue + (i * 4), &bits, 4);
            }
        } else {
            // Handle 64-bit lanes (8 double values)
            for (int i = 0; i < 8; i++) {
                uint64_t bits;
                double dval = value.info.arrays.doubleArray[i];
                std::memcpy(&bits, &dval, sizeof(double));
                
                // Write to the appropriate position in the byte array
                std::memcpy(zmmValue + (i * 8), &bits, 8);
            }
        }
        
        // Write the bytes to the register using icicle_reg_write_bytes
        int result = icicle_reg_write_bytes(icicle, lowerRegName.c_str(), zmmValue, sizeof(zmmValue));
        if (result != 0) {
            LOG_ERROR("Failed to write to ZMM register " << regName << ", result=" << result);
            return false;
        }
        return true;
    }
    
    return false;
}

registerValueInfoT getRegister(const std::string& name){
    registerValueInfoT res = {false, 0};
    std::string regName = name;

    if (name.contains('[') && name.contains(']') && name.contains(':')){
        regName = name.substr(0, name.find_first_of('['));
    }

    if (!codeHasRun){
        constexpr registerValueInfoT ret = {false, 0x00};
        return ret;
    }

    const auto value = getRegisterValue(regName);
    res = {true, value};
    return res;
}


Icicle* initIC()
{
    const auto vm = icicle_new(codeInformation.archStr, false, true, false, false, false, false, false, false);
    if (!vm)
    {
        printf("Failed to initialize VM\n");
        return nullptr;
    }

    LOG_INFO("Initiation complete...");
    initArch();


    if (!breakpointLines.empty())
    {
        for (auto& line : breakpointLines)
        {
            // addBreakpointToLine(line);
            icicle_add_breakpoint(vm, lineNoToAddress(line));
        }
    }

    icicle = vm;
    return vm;
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


void instructionHook(void* userData, const uint64_t address)
{
    // Update UI safely with current line
    // const std::string lineNoStr = addressLineNoMap[std::to_string(address)];
    // if (!lineNoStr.empty()) {
    //     int lineNo = std::atoi(lineNoStr.c_str());
    //     if (lineNo > 0) {
    //         safeHighlightLine(lineNo - 1);
    //     }
    // }
}
bool updateStack = false;
void stackWriteHook(void* data, uint64_t address, uint8_t size, const uint64_t valueWritten)
{
    updateStack = true;
}

void hookStackWrite(uc_engine *uc, const uint64_t address, const uint32_t size, void *user_data) {
    updateStack = true;
}

bool preExecutionSetup(const std::string& codeIn)
{
    initRegistersToDefinedVals();
    if (codeBuf == nullptr){
        codeBuf = static_cast<uint8_t *>(malloc(CODE_BUF_SIZE));
        memset(codeBuf, 0, CODE_BUF_SIZE);
        LOG_DEBUG("Code buffer allocated!");
    }

    const auto *code = (uint8_t *)(codeIn.c_str());
    memcpy(codeBuf, code, codeIn.length());

    // TODO: Add a way to make stack executable
    auto e = icicle_mem_map(icicle, ENTRY_POINT_ADDRESS, CODE_BUF_SIZE, MemoryProtection::ExecuteReadWrite);
    if (e == -1)
    {
        LOG_ERROR("Failed to map memory for writing code!");
        return false;
    }

    auto k = icicle_mem_write(icicle, ENTRY_POINT_ADDRESS, codeBuf, CODE_BUF_SIZE - 1);
    size_t l;
    auto j = icicle_mem_read(icicle, ENTRY_POINT_ADDRESS, CODE_BUF_SIZE, &l);
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

    // Signal that debugging setup is complete and ready for execution
    {
        std::lock_guard<std::mutex> lk(debugReadyMutex);
        isDebugReady = true;
    }
    debugReadyCv.notify_all();
    LOG_DEBUG("Debug setup complete, signaled ready.");

    return true;
}

bool createStack(Icicle* ic)
{
    LOG_INFO("Creating stack...");
    if (ic == nullptr)
    {
     ic = initIC();
    if (!ic){
        LOG_ERROR("Icicle initilisation failed... Quitting!");
        return false;
    }

    }
    LOG_INFO("Checking mappings...");
    // Check if the stack region is already mapped
    bool already_mapped = false;
    size_t region_count = 0;
    MemRegionInfo* regions = icicle_mem_list_mapped(ic, &region_count);
    
    if (regions) {
        for (size_t i = 0; i < region_count; i++) {
            // Check if this region overlaps with our stack region
            if ((regions[i].address <= STACK_ADDRESS && 
                 regions[i].address + regions[i].size > STACK_ADDRESS) ||
                (regions[i].address >= STACK_ADDRESS && 
                 regions[i].address < STACK_ADDRESS + STACK_SIZE)) {
                LOG_INFO("Stack region already mapped - skipping map operation");
                already_mapped = true;
                break;
            }
        }
        if (!already_mapped)
        {
            LOG_ERROR("stack regions are not mapped yet!");
        }
        icicle_mem_list_mapped_free(regions, region_count);
    }

    uint8_t* zeroBuf = (uint8_t*)malloc(STACK_SIZE);
    memset(zeroBuf, 0, STACK_SIZE);
    LOG_INFO("Stack mapping if not done already.");
    // Only map if not already mapped
    if (!already_mapped) {
        const auto mapped = icicle_mem_map(ic, STACK_ADDRESS, STACK_SIZE, MemoryProtection::ReadWrite);
        if (mapped == -1)
        {
            LOG_ERROR("Icicle was unable to map memory for the stack.");
            free(zeroBuf);
            return false;
        }
        for (uint64_t off = 0; off < STACK_SIZE; off += 0x1000) {
            size_t out = 0;
            // A 1‑byte read is enough to trigger the lazy page allocation
            icicle_mem_read(icicle, STACK_ADDRESS + off, 1, &out);
        }
    }
    LOG_INFO("Attempting a mem_write");
    const auto mapped = icicle_mem_write(ic, STACK_ADDRESS, zeroBuf, STACK_SIZE);
    if (mapped == -1)
    {
        LOG_WARNING("Icicle was unable to zero memory for the stack.");
        LOG_WARNING("Something may be wrong, proceeding anyways...");
    }
    free(zeroBuf);

    const uint64_t stackBase = STACK_ADDRESS + STACK_SIZE;
    icicle_reg_write(ic, archSPStr, stackBase);
    icicle_reg_write(ic, archBPStr, stackBase);
    size_t outSize{};
    const auto s = icicle_mem_read(ic, STACK_ADDRESS, STACK_SIZE, &outSize);
    if (!s)
    {
        LOG_ERROR("Failed to read the stack base pointer, quitting!!");
    }

    stackArraysZeroed = false;
    LOG_INFO("Stack created successfully!");
    return true;
}

bool resetState(){
    LOG_INFO("Resetting state...");
    criticalSection.lock();

    {
        std::lock_guard<std::mutex> lk(debugReadyMutex);
        isDebugReady = false;
    }

    codeHasRun = false;
    stepClickedOnce = false;
    continueOverBreakpoint = false;
    debugPaused = false;
    skipBreakpoints = false;
    executionComplete = false;
    wasStepOver = false;
    wasJumpAndStepOver = false;
    stackArraysZeroed = false;
    stoppedAtBreakpoint = false;
    codeCurrentLen = 0;
    codeFinalLen = 0;
    lineNo = 0;
    expectedIP = 0;

    assembly.clear();
    assembly.str("");
    instructionSizes.clear();

    editor->ClearExtraCursors();
    editor->ClearSelections();
    editor->HighlightDebugCurrentLine(-1);

    if (icicle != nullptr)
    {
        icicle_free(icicle);
        icicle = nullptr;
    }

    if (snapshot != nullptr)
    {
        icicle_vm_snapshot_free(snapshot);
        snapshot = nullptr;
    }

    labels.clear();
    emptyLineNumbers.clear();
    addressLineNoMap.clear();
    labelLineNoMapInternal.clear();
    labelLineNoRange.clear();

    labels = {};
    emptyLineNumbers = {};
    labelLineNoRange = {};
    labelLineNoMapInternal = {};

     if (getBytes(selectedFile).empty()) {
         criticalSection.unlock();
        return false;
    }

    for (const auto &key: registerValueMap | std::views::keys){
        registerValueMap[key] = "0x00";
    }

    stackArraysZeroed = false;
    LOG_DEBUG("State reset completed!");
    criticalSection.unlock();
    return true;
}

uint64_t lineNoToAddress(const uint64_t& lineNo)
{
    for (auto& pair : addressLineNoMap)
    {
        if (std::atoi(pair.second.c_str()) == lineNo)
        {
            return std::stoull(pair.first);
        }
    }

    return 0;
}

bool isSilentBreakpoint(const uint64_t& lineNo)
{
    if (icicle == nullptr)
    {
        return false;
    }

    size_t outSize{};
    const uint64_t* breakpointList = icicle_breakpoint_list(icicle, &outSize);
    if (breakpointList == nullptr)
    {
        return false;
    }

    for (int i = 0; i < outSize; i++)
    {
        if (breakpointList[i] == lineNoToAddress(lineNo))
        {
            if (std::ranges::find(breakpointLines, lineNo) == breakpointLines.end())
            {
                // a silent breakpoint is a breakpoint which was internally added by
                // our code and not by the user
                return true;
            }
            return false;
        }
    }

    return false;
}

bool isCodeExecutedAlready = false;
bool checkStatusUpdateState(const size_t& instructionCount, RunStatus status, const uint64_t& oldBPAddr)
{
    const uintptr_t ip = icicle_get_pc(icicle);
    LOG_INFO("Execution completed! with status code: " << status << " address: " << std::hex << ip);

    const std::string lineNoStr = addressLineNoMap[std::to_string(ip)];
    if (!lineNoStr.empty()) {
        const int lineNo = std::atoi(lineNoStr.c_str());
        if (lineNo > 0) {
            safeHighlightLine(lineNo - 1);
        }
    }

    if (status == RunStatus::Breakpoint)
    {
        LOG_DEBUG("Breakpoint reached at address " << icicle_get_pc(icicle));

        const auto lineNo = addressLineNoMap[std::to_string(ip)];
        if (!lineNo.empty())
        {
            if (isSilentBreakpoint(strtoll(lineNo.c_str(), nullptr, 10)))
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

    return true;
}

bool executeCode(Icicle* icicle, const size_t& instructionCount)
{
    if (icicle == nullptr)
    {
        LOG_ERROR("Attempted to run code when icicle was not initialised!");
        return false;
    }

    if (executionComplete == true)
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
        if (!icicle_add_breakpoint(icicle, lineNoToAddress(lastInstructionLineNo)))
        {
           LOG_ERROR("Failed to add breakpoint at the last instruction. The program may end unexpectedly.");
        }

        status = icicle_run(icicle);
        if (runUntilHere)
        {
            runUntilHere = false;
            LOG_INFO("Run until here set to false");
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

bool isCodeRunning = false;
bool skipBreakpoints = false;
bool runningAsContinue = false;
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

    uint64_t ip = getRegisterValue(archIPStr).eightByteVal;
    isCodeRunning = true;
    if (instructionCount == 1) {
        skipBreakpoints = true;
    }

    size_t siz{};
    RunStatus status{};

    executeCode(icicle, instructionCount); // This contains the core execution

    // Update state *after* execution
    ip = icicle_get_pc(icicle);
    editor->HighlightDebugCurrentLine(std::atoll(addressLineNoMap[std::to_string(icicle_get_pc(icicle))].c_str()));
    isCodeRunning = false; // Mark as not running *after* execution
    LOG_DEBUG("Code executed by " << instructionCount << ((instructionCount > 1) ? " steps" : " step") << ".");

    if (executionComplete){
        editor->HighlightDebugCurrentLine(lastInstructionLineNo-1);
        LOG_DEBUG("Execution complete after step.");
        return true;
    }

    {
        if (!saveICSnapshot(icicle)){
            LOG_ERROR("Failed to save snapshot after step.");
            return false;
        }

        ip = icicle_get_pc(icicle);
        if (ip != expectedIP){
            expectedIP = ip;
        }

        const std::string str =  addressLineNoMap[std::to_string(ip)];
        if (!str.empty() && (!executionComplete)){
            lineNo = std::atoi(str.c_str());
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

uint64_t addressToLineNo(const uint64_t& address)
{
    return strtoll(addressLineNoMap[std::to_string(address)].c_str(), nullptr, 10);
}

bool addBreakpoint(const uint64_t& address, const bool& silent)
{
    if (icicle == nullptr)
    {
        return false;
    }

    if (icicle_add_breakpoint(icicle, address))
    {
       return true;
    }

    return false;
}

bool addBreakpointToLine(const uint64_t& lineNo, const bool& silent)
{
    const bool skipCheck = icicle == nullptr;

    if (!addBreakpoint(lineNoToAddress(lineNo + 1), silent) && !skipCheck)
    {
        return false;
    }

    if (!silent)
    {
        breakpointLines.push_back(lineNo + 1);
        editor->HighlightBreakpoints(lineNo);
    }

    return true;
}

bool runCode(const std::string& codeIn, const bool& execCode)
{
    LOG_INFO("Running code...");
    if (!preExecutionSetup(codeIn)) {
        return false;
    }

    auto line = addressLineNoMap[std::to_string(ENTRY_POINT_ADDRESS)];
    if (line.empty()){
        line = "1";
    }

    auto val = std::atoi(line.data());
    editor->HighlightDebugCurrentLine(val - 1);
    LOG_DEBUG("Highlight from runCode");

    if (execCode || (stepClickedOnce)){
        addBreakpointToLine(lastInstructionLineNo, true);
        if (!executeCode(icicle, 0))
        {
            LOG_ERROR("Failed to run code.");
        }

        editor->HighlightDebugCurrentLine(lastInstructionLineNo);
        if (runningTempCode){
            icicle_vm_snapshot(icicle);
            updateRegs();
        }
    }

    if (!execCode){
        free(codeBuf);
        codeBuf = nullptr;
    }
    else {
        saveICSnapshot(icicle);

        line = addressLineNoMap[std::to_string(ENTRY_POINT_ADDRESS)];
        if (line.empty()){
            line = "1";
        }

        val = std::atoi(line.data());
        editor->HighlightDebugCurrentLine(val - 1);
        LOG_DEBUG("Highlight from runCode");
        stepClickedOnce = true;
    }

    updateRegs();
    LOG_INFO("Ran code successfully!");
    codeHasRun = true;
    return true;
}

Icicle* tempIcicle = nullptr;
VmSnapshot* tempSnapshot = nullptr;

bool runTempCode(const std::string& codeIn, const uint64_t instructionCount){
    LOG_INFO("Running " << instructionCount << " temporary instructions...");

    resetState();
    runningTempCode = true;
    runCode(codeIn, instructionCount);

    tempIcicle = icicle;
    constexpr auto size = sizeof(VmSnapshot);
    tempSnapshot = static_cast<VmSnapshot*>(malloc(size));
    memcpy(tempSnapshot, snapshot, size);

    updateRegs(true);
    free(tempSnapshot);
    return true;
}