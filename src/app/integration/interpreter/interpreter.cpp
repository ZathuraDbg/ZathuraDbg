#include "interpreter.hpp"

#include <sys/stat.h>
uintptr_t ENTRY_POINT_ADDRESS = 0x10000;
uintptr_t MEMORY_ALLOCATION_SIZE = 2 * 1024 * 1024;
uintptr_t DEFAULT_STACK_ADDRESS = 0x300000;
uintptr_t STACK_ADDRESS = DEFAULT_STACK_ADDRESS;
uint64_t  CODE_BUF_SIZE = 0x3000;
uintptr_t STACK_SIZE = 5 * 1024 * 1024;
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

std::vector<uint64_t> breakpointLines = {};

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

bool removeBreakpoint(const int& lineNo) {
    breakpointMutex.lock();

    bool success = false;
    //
    if (breakpointLines.empty()) {
        breakpointMutex.unlock();
        return success;
    }
    //
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

registerValueT getRegisterValue(std::string regName){
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
        registerValueInfoT ret = {false, 0x00};
        // if (getRegisterActualSize(toUpperCase(name)) == 128) {
        //     ret.registerValueUn.info.is128bit = true;
        // }
        // else if (getRegisterActualSize(toUpperCase(name)) == 256){
        //     ret.registerValueUn.info.is256bit = true;
        // }
        // else if (getRegisterActualSize(toUpperCase(name)) == 512) {
        //     ret.registerValueUn.info.is512bit = true;
        // }

        return ret;
    }

    const auto value = getRegisterValue(regName);
    res = {true, value};
    return res;
}


Icicle* initIC()
{
    const auto vm = icicle_new("x86_64", false, false, false, false, false, false, false, false);
    if (!vm)
    {
        printf("Failed to initialize VM\n");
        return nullptr;
    }

    LOG_INFO("Initiation complete...");
    initArch();
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


void instructionHook(void* userData, uint64_t address)
{
    std::cout << "Instruction hook called!" << std::endl;
}

// void hook(uc_engine *uc, const uint64_t address, const uint32_t size, void *user_data){
//     std::string currentLabel{};
//
//     int lineNumber = -1;
//     const std::string str = addressLineNoMap[std::to_string(address)];
//     if (!str.empty()){
//         lineNumber = std::atoi(str.c_str());
//     }
//     else{
//         lineNumber = -1;
//     }
//
//     bool jumpDetected = false;
//     if ((!debugModeEnabled && !debugRun) || (executionComplete) || (pauseNext && pausedLineNo != lineNumber)){
//         LOG_DEBUG("Execution halted.");
//         uc_emu_stop(uc);
//         saveUCContext(uc, context);
//
//         if (executionComplete){
//             editor->HighlightDebugCurrentLine(lastInstructionLineNo - 1);
//         }
//
//         if (pauseNext && pausedLineNo != lastLineNo){
//             LOG_DEBUG("Pause next detected!");
//             pauseNext = false;
//         }
//         criticalSection.unlock();
//         return;
//     }
//
//     if (!runningAsContinue) {
//      for (auto &[label, range]: labelLineNoRange) {
//         if (lineNo > range.first && (lineNo <= range.second)) {
//             currentLabel = label;
//             break;
//         }
//     }
//     }
//
//     if (stepOver) {
//         wasStepOver = true;
//     }
//
//     LOG_DEBUG("At lineNo: " << lineNumber);
//     if (lineNumber == runUntilLine){
//         LOG_DEBUG("Run until here detected!");
//         LOG_DEBUG("At lineNo: " << lineNumber);
//         runUntilLine = 0;
//         runUntilHere = false;
//         uc_emu_stop(uc);
//         saveUCContext(uc, context);
//     }
//
//     if (eraseTempBP) {
// //      erase the temporary breakpoint
//         breakpointMutex.lock();
//         LOG_DEBUG("Removing step over breakpoint line number: " << stepOverBPLineNo);
//         if (!breakpointLines.empty()) {
//             breakpointLines.erase(std::ranges::find(breakpointLines, stepOverBPLineNo));
//         }
//
//         breakpointMutex.unlock();
//         stepOverBPLineNo = -1;
//         eraseTempBP = false;
//     }
//
//     if (expectedIP == 0){
//         expectedIP = address;
//     }
//
//     if (lineNumber == lastInstructionLineNo){
//         executionComplete = true;
//     }
//
//     uint64_t ip = getRegisterValue(getArchIPStr(codeInformation.mode), false).eightByteVal;
//
//
//     if (ip != expectedIP && expectedIP != 0 && !currentLabel.empty()) {
//         if (lastLineNo == labelLineNoRange[currentLabel].second && lineNumber != lastLineNo) {
//             uc_emu_stop(uc);
//             saveUCContext(uc, context);
//         }
//     }
//
//     if (debugModeEnabled && !skipBreakpoints){
//         if (ip != expectedIP && (ip > expectedIP)){
//             LOG_INFO("Jump detected!");
//             jumpDetected = true;
//             updateRegs();
//
//             /* The following check makes sure that the
//              * step in behavior stays consistent even when
//              * the step out routine is used in order to
//              * fix an issue with unicorn.
//            */
//             if (stepInBypassed && !jumpAfterBypass) {
//                 jumpAfterBypass = true;
//                 stepInBypassed = false;
//             }
//             else if (jumpAfterBypass) {
//                 LOG_DEBUG("Program paused after a jump is recieved after stepIn bypass");
//                 uc_emu_stop(uc);
//                 jumpAfterBypass = false;
//                 stepInBypassed = false;
//             }
//
//             if (stepIn){
//                 LOG_DEBUG("Step in detected!");
//                 const std::string breakPointLinNo = addressLineNoMap[std::to_string(ip)];
//                 tempBPLineNum = std::atoi(breakPointLinNo.c_str());
//                 if (!breakPointLinNo.empty()){
//                     breakpointMutex.lock();
//                     breakpointLines.push_back(tempBPLineNum);
//                     breakpointMutex.unlock();
//                 }
//             }
//             expectedIP = ip;
//         }
//
//         editor->HighlightDebugCurrentLine(lineNumber - 1);
//         if (std::ranges::find(breakpointLines, lineNumber) != breakpointLines.end() && (!skipBreakpoints)){
//             editor->HighlightDebugCurrentLine(lineNumber - 1);
//             LOG_DEBUG("Highlight from hook - breakpoint found at lineNo " << lineNumber);
//             if (((runningAsContinue && lineNumber == stepOverBPLineNo))) {
//                 removeBreakpoint(stepOverBPLineNo);
//             }
//             else if (!continueOverBreakpoint){
//                 LOG_DEBUG("Breakpoint hit!");
//                 uc_emu_stop(uc);
//                 saveUCContext(uc, context);
//                 continueOverBreakpoint = true;
//                 return;
//             }
//             else{
//                 continueOverBreakpoint = false;
//             }
//         }
//
//         if (tempBPLineNum != -1){
//             removeBreakpoint(tempBPLineNum);
//         }
//     }
//     if (stepOverBPLineNo != -1){
//         eraseTempBP = true;
//     }
//
//    if (!wasJumpAndStepOver) {
//         wasJumpAndStepOver = jumpDetected && wasStepOver;
//    }
//
//     if (debugPaused && stepIn){
//         LOG_DEBUG("Step In detected after pause!");
//         stepIn = false;
//         pauseNext = true;
//         pausedLineNo = lineNumber;
//     }
//
//     saveUCContext(uc, context);
//     codeCurrentLen += size;
//     expectedIP += size;
//     lastLineNo = lineNumber;
//     criticalSection.unlock();
// }

bool updateStack = false;
void stackWriteHook(void* data, uint64_t address, uint8_t size, const uint8_t* value_read)
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
    auto e = icicle_mem_map(icicle, ENTRY_POINT_ADDRESS, MEMORY_ALLOCATION_SIZE, MemoryProtection::ExecuteReadWrite);
    if (e == -1)
    {
        LOG_ERROR("Failed to map memory for writing code!");
        return false;
    }

    auto k = icicle_mem_write(icicle, ENTRY_POINT_ADDRESS, codeBuf, CODE_BUF_SIZE - 1);
    size_t l;
    auto j = icicle_mem_read(icicle, ENTRY_POINT_ADDRESS, CODE_BUF_SIZE, &l);
    icicle_set_pc(icicle, ENTRY_POINT_ADDRESS);

    if (snapshot == nullptr)
    {
        icicle_vm_snapshot(icicle);
    }

    uint32_t instructionHookID = icicle_add_execution_hook(icicle, instructionHook, nullptr);
    uint32_t stackWriteHookID = icicle_add_mem_read_hook(icicle, stackWriteHook, nullptr, STACK_ADDRESS + STACK_SIZE, STACK_ADDRESS);
    return true;
}

bool createStack(Icicle* ic)
{
    LOG_INFO("Creating stack...");
    auto icicle = initIC();
    if (!icicle){
        LOG_ERROR("Icicle initilisation failed... Quitting!");
        return false;
    }

    uint8_t* zeroBuf = (uint8_t*)malloc(STACK_SIZE);

    memset(zeroBuf, 0, STACK_SIZE);
    auto mapped = icicle_mem_map(icicle, STACK_ADDRESS, STACK_SIZE, MemoryProtection::ReadWrite);
    if (mapped == -1)
    {
        LOG_ERROR("Icicle was unable to map memory for the stack.");
        return false;
    }

    mapped = icicle_mem_write(icicle, STACK_ADDRESS, zeroBuf, STACK_SIZE);
    if (mapped == -1)
    {
        LOG_WARNING("Icicle was unable to zero memory for the stack.");
        LOG_WARNING("Something may be wrong, proceeding anyways...");
    }

    uint64_t stackBase = STACK_ADDRESS + STACK_SIZE;
    icicle_reg_write(icicle, archSPStr, stackBase);
    icicle_reg_write(icicle, archBPStr, stackBase);
    size_t outSize{};
    auto s = icicle_mem_read(icicle, STACK_ADDRESS, STACK_SIZE, &outSize);
    if (!s)
    {
        LOG_ERROR("Failed to read the stack base pointer, quitting!!");
    }

    stackArraysZeroed = false;
    LOG_INFO("Stack created successfully!");
    return true;
}

// bool createStack(void* unicornEngine){
//     LOG_INFO("Creating stack...");
//
//     if (!ucInit(unicornEngine)){
//         LOG_ERROR("Unicorn engine initilisation failed... Quitting!");
//         return false;
//     }
//
//     auto *zeroBuf = static_cast<uint8_t*>(malloc(STACK_SIZE));
//
//     memset(zeroBuf, 0, STACK_SIZE);
//     const auto err = uc_mem_map(uc, STACK_ADDRESS, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE);
//     if (err && err != UC_ERR_MAP){
//         LOG_ERROR("Failed to memory map the stack!!");
//         return false;
//     }
//
//     if (err == UC_ERR_MAP) {
//         LOG_WARNING("Unicorn Mapping error triggered while initialising the stack.");
//         LOG_WARNING("The most probable cause is the workaround, if it still causes issues please report it otherwise ignore this.");
//         return true;
//     }
//
//     if (uc_mem_write(uc, STACK_ADDRESS, zeroBuf, STACK_SIZE)) {
//         LOG_ERROR("Failed to write to the stack!!");
//         return false;
//     }
//
//     auto [sp, bp] = getArchSBPStr(codeInformation.mode);
//     const uint64_t stackBase = STACK_ADDRESS + STACK_SIZE;
//     if (uc_reg_write(uc, regNameToConstant(sp), &stackBase)){
//         LOG_ERROR("Failed to write the stack pointer to base pointer, quitting!!");
//         return false;
//     }
//
//     if (uc_reg_write(uc, regNameToConstant(bp), &stackBase)){
//         printf("Failed to write base pointer to memory, quitting!\n");
//         return false;
//     }
//
//     free(zeroBuf);
//     stackArraysZeroed = false;
//     LOG_INFO("Stack created successfully!");
//     return true;
// }

bool resetState(){
    LOG_INFO("Resetting state...");
    criticalSection.lock();
    codeHasRun = false;
    stepClickedOnce = false;
    continueOverBreakpoint = false;
    debugPaused = false;
    skipBreakpoints = false;
    executionComplete = false;
    wasStepOver = false;
    wasJumpAndStepOver = false;
    stackArraysZeroed = false;
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

//     if (uc != nullptr){
//         if (tempUC == uc){
//             tempUC = nullptr;
//         }
//
// //        uc_close(uc);
//         uc = nullptr;
//     }

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

    // if (context != nullptr){
    //     if (tempContext == context){
    //         tempContext = nullptr;
    //     }
    //
    //     uc_context_free(context);
    //     context = nullptr;
    // }

    // if (tempContext != nullptr){
    //     uc_context_free(tempContext);
    //     tempContext = nullptr;
    // }

    // if (tempUC != nullptr){
    //     uc_close(tempUC);
    //     tempUC = nullptr;
    // }

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

    if (!createStack(icicle)){
        LOG_ERROR("Unable to create stack!");
        criticalSection.unlock();
        return false;
    }

    stackArraysZeroed = false;
    LOG_DEBUG("State reset completed!");
    criticalSection.unlock();
    return true;
}

bool isCodeRunning = false;
bool skipBreakpoints = false;
bool runningAsContinue = false;
bool stepCode(const size_t instructionCount){
    LOG_DEBUG("Stepping into code...");
    if (isCodeRunning || executionComplete){
        criticalSection.unlock();
        return true;
    }

    uint64_t ip = getRegisterValue(archIPStr).eightByteVal;
    execMutex.lock();
    isCodeRunning = true;
    if (instructionCount == 1) {
        skipBreakpoints = true;
    }

    criticalSection.lock();
    size_t siz{};
    auto j = icicle_mem_read(icicle, ENTRY_POINT_ADDRESS, CODE_BUF_SIZE, &siz);
    assert(j != NULL);
    RunStatus status{};
    if (instructionCount != 0)
    {
        status = icicle_step(icicle, instructionCount);
    }
    else
    {
        status = icicle_run(icicle);
    }
    auto k = icicle_get_exception_code(icicle);
    ip = icicle_get_pc(icicle);
    editor->HighlightDebugCurrentLine(std::atoll(addressLineNoMap[std::to_string(icicle_get_pc(icicle))].c_str()));
    isCodeRunning = false;
    execMutex.unlock();
    LOG_DEBUG("Code executed by " << instructionCount << ((instructionCount>1) ? " step" : " steps") << ".");

    if (executionComplete){
        LOG_DEBUG("Execution complete...");
        return true;
    }

    {
        if (!saveICSnapshot(icicle)){
            criticalSection.unlock();
            return false;
        }

        ip = icicle_get_pc(icicle);
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
            criticalSection.unlock();
            return true;
        }
    }

    saveICSnapshot(icicle);
    criticalSection.unlock();

    codeHasRun = true;

    if (skipBreakpoints){
        skipBreakpoints = !skipBreakpoints;
    }

    if (runningAsContinue) {
        runningAsContinue = !runningAsContinue;
    }

    return true;
}

bool runCode(const std::string& codeIn, uint64_t instructionCount)
{
    LOG_INFO("Running code...");
    if (!preExecutionSetup(codeIn)) {
        return false;
    }

    if (instructionCount != 1 || (stepClickedOnce)){
        const RunStatus status = icicle_run_until(icicle, ENTRY_POINT_ADDRESS + CODE_BUF_SIZE);
        if (status == RunStatus::Breakpoint)
        {
            LOG_DEBUG("Breakpoint reached at address " << icicle_get_pc(icicle));
        }
        else if (status == RunStatus::Unimplemented)
        {
            LOG_DEBUG("Unimplemented instruction at address " << icicle_get_pc(icicle));
        }
        else if (status == RunStatus::OutOfMemory)
        {
            LOG_DEBUG("Ran out of memory at: " << icicle_get_pc(icicle));
        }

        if (runningTempCode){
            icicle_vm_snapshot(icicle);
            updateRegs();
        }

        if (status == RunStatus::Killed) {
            saveICSnapshot(icicle);
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
        saveICSnapshot(icicle);

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

Icicle* tempIcicle = nullptr;
VmSnapshot* tempSnapshot = nullptr;

bool runTempCode(const std::string& codeIn, uint64_t instructionCount){
    LOG_INFO("Running " << instructionCount << " temporary instructions...");

    resetState();
    runningTempCode = true;
    runCode(codeIn, instructionCount);

    tempIcicle = icicle;
    // const auto size = uc_context_size(uc);
    constexpr auto size = sizeof(VmSnapshot);
    tempSnapshot = static_cast<VmSnapshot*>(malloc(size));
    memcpy(tempSnapshot, snapshot, size);

    updateRegs(true);
    icicle_vm_snapshot_free(tempSnapshot);
    return true;
}