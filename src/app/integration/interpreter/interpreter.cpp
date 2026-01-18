#include "interpreter.hpp"

// Forward declarations for BreakpointManager callback functions
static uint64_t lineNoToAddressCallback(uint64_t lineNo);
static uint64_t addressToLineNoCallback(uint64_t address);

// Initialize BreakpointManager callbacks early
static void initBreakpointManagerCallbacks() {
    auto& bpMgr = getBreakpointManager();
    bpMgr.setLineToAddressFunc(lineNoToAddressCallback);
    bpMgr.setAddressToLineFunc(addressToLineNoCallback);
    bpMgr.setHighlightCallback([](uint64_t lineNo) {
        if (editor) {
            editor->HighlightBreakpoints(lineNo);
        }
    });
    bpMgr.setRemoveHighlightCallback([](uint64_t lineNo) {
        if (editor) {
            editor->RemoveHighlight(lineNo);
        }
    });
}

// Callback implementation for lineNoToAddress
static uint64_t lineNoToAddressCallback(uint64_t lineNo) {
    if (lineNo == 0)
        return ENTRY_POINT_ADDRESS;

    for (auto& pair : addressLineNoMap) {
        if (pair.second == lineNo)
            return pair.first;
    }
    return 0;
}

// Callback implementation for addressToLineNo
static uint64_t addressToLineNoCallback(uint64_t address) {
    auto it = addressLineNoMap.find(address);
    if (it != addressLineNoMap.end()) {
        return it->second;
    }
    return 0;
}

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
// These variables are kept for backward compatibility
// The BreakpointManager also tracks similar state internally
bool stoppedAtBreakpoint = false;
bool nextLineHasBreakpoint = false;
bool addBreakpointBack = false;
bool skipEndStep = false;
bool isEndBreakpointSet = false;

// breakpointLines is now managed by BreakpointManager
// This reference provides backward compatibility
std::vector<uint64_t>& breakpointLines = getBreakpointManager().getBreakpointLinesRef();

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

    const auto lineNumber = addressLineNoMap[instructionPointer];

    return (lineNumber ? lineNumber : -1);
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

// void printBreakpoints()
// {
//     size_t count;
//     uint64_t *bpList = icicle_breakpoint_list(icicle, &count);
//     for (size_t i = 0; i < count; i++)
//     {
//         LOG_INFO("Breakpoint #" << i + 1 << " at address: " << std::hex << bpList[i] << std::hex << " at line: " << (addressLineNoMap[std::to_string(bpList[i])]));
//     }
// }

bool removeBreakpointFromLineNo(const uint64_t& lineNo) {
    auto& bpMgr = getBreakpointManager();

    // Check if this is a silent breakpoint
    if (bpMgr.isSilentBreakpoint(lineNo)) {
        // We don't need to remove silent breakpoints via this function
        LOG_ALERT("Attempt to remove a silent breakpoint. Ignoring.");
        return true;
    }

    // Use BreakpointManager to remove the user breakpoint
    // It handles thread safety, VM interaction, and UI updates
    return bpMgr.removeUserBreakpoint(lineNo);
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

registerValueT read256BitRegister(const std::string& regName)
{
    uint8_t arrSize = use32BitLanes ? 8 : 4;
    registerValueT regValue{};
    uint8_t ymmValue[32] = {0};
    size_t outSize;

    const int result = icicle_reg_read_bytes(icicle, toLowerCase(regName).c_str(), ymmValue, sizeof(ymmValue), &outSize);
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

registerValueT read128BitRegisterValue(const std::string& regName)
{
    uint8_t regValArray[16] = {0};
    size_t outSize;
    const int result = icicle_reg_read_bytes(icicle, toLowerCase(regName).c_str(), regValArray, sizeof(regValArray), &outSize);

    if (result != 0 || outSize != sizeof(regValArray)) {
        LOG_ERROR("Failed to read register " << regName << ", result=" << result << ", outSize=" << outSize);
        return {.eightByteVal = 0};
    }

    uint64_t upperHalf, lowerHalf;
    std::memcpy(&lowerHalf, regValArray, 8);
    std::memcpy(&upperHalf, regValArray + 8, 8);

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

registerValueT x86GetRegisterValue(const size_t size, const std::string& regName)
{
    if (size <= 64) {
        uint64_t valTemp64;
        icicle_reg_read(icicle, toLowerCase(regName).c_str(), &valTemp64);
        return {.eightByteVal = valTemp64};
    }
    if (size == 128){
        return read128BitRegisterValue(regName);
    }
    else if (size == 256){
        return read256BitRegister(regName);
    }
    else if (size == 512) {
        LOG_WARNING("The underlying emulation engine does not currently support 512-bit registers!");
        // uint8_t arrSize = use32BitLanes ? 16 : 8;
        // registerValueT regValue{};
        // uint8_t zmmValue[64] = {0};
        // size_t outSize;
        //
        // int result = icicle_reg_read_bytes(icicle, lowerRegName.c_str(), zmmValue, sizeof(zmmValue), &outSize);
        // if (result != 0 || outSize != sizeof(zmmValue)) {
        //     LOG_ERROR("Failed to read register " << regName << ", result=" << result << ", outSize=" << outSize);
        //     return {.eightByteVal = 0};
        // }
        //
        // if (!use32BitLanes){
        //     double valueArray[arrSize]{};
        //
        //     // Convert bytes to doubles
        //     for (int i = 0; i < 8; i++) {
        //         uint64_t bits;
        //         std::memcpy(&bits, &zmmValue[i * 8], 8);
        //         // Properly interpret the bits as a double
        //         double val;
        //         std::memcpy(&val, &bits, sizeof(double));
        //         valueArray[i] = val;
        //     }
        //
        //     regValue = {.doubleVal = 0.0f};
        //
        //     for (int i = 0; i < 8; i++){
        //         regValue.info.arrays.doubleArray[i] = valueArray[i];
        //     }
        //
        //     for (double i : valueArray){
        //         if (i != 0){
        //             regValue.doubleVal = 1.0f;
        //             break;
        //         }
        //     }
        //     regValue.info.is512bit = true;
        //     return regValue;
        // }
        // else{
        //     float valueArray[arrSize]{};
        //
        //     // Convert bytes to floats (16 floats in a 512-bit register)
        //     for (int i = 0; i < 16; i++) {
        //         uint32_t bits;
        //         std::memcpy(&bits, &zmmValue[i * 4], 4);
        //         valueArray[i] = *reinterpret_cast<float*>(&bits);
        //     }
        //
        //     regValue = {.doubleVal = (valueArray[0])};
        //
        //     for (int i = 0; i < 16; i++){
        //         regValue.info.arrays.floatArray[i] = valueArray[i];
        //     }
        //
        //     for (float i : regValue.info.arrays.floatArray){
        //         if (i != 0){
        //             regValue.doubleVal = regValue.floatVal = 1.0f;
        //             break;
        //         }
        //     }
        //
        //     regValue.info.is512bit = true;
        //     return regValue;
        // }
    }
    return {.eightByteVal = 00};
}

registerValueT armGetRegisterValue(const size_t size, const std::string& regName)
{
    registerValueT regValue{
        .eightByteVal = 0,
        .floatVal = 0,
        .doubleVal = 0,
        .info = {
            .is128bit = false,
            .is256bit = false,
            .is512bit = false,
            .isFloatReg = false,
            .isDoubleReg = false,
            .arrays = {
                .doubleArray = {}
            }
        }
    };

    if (size == 32)
    {
        if (vfpRegs.contains(regName))
        {
            uint8_t vfpRegVal[4];
            size_t outSize;
            const int res = icicle_reg_read_bytes(icicle, toLowerCase(regName).c_str(), vfpRegVal, 4, &outSize);
            if (res != 0 || outSize != 4)
            {
                LOG_ERROR("Failed to read vfp register " << regName << "!");
                return {.eightByteVal = 0};
            }

            regValue.info.isFloatReg = true;
            std::memcpy(&regValue.floatVal, vfpRegVal, 4);
        }
        else
        {
            uint64_t val;
            const int res = icicle_reg_read(icicle, toLowerCase(regName).c_str(), &val);
            if (res != 0)
            {
                LOG_ERROR("Failed to read register " << regName << "!");
                return {.eightByteVal = 0};
            }

            regValue.eightByteVal = val;
        }

        return regValue;
    }
    else if (size == 64)
    {
        const std::unordered_set<std::string> dRegs = {
            "d0",  "d1",  "d2",  "d3",  "d4",  "d5",  "d6",  "d7",
            "d8",  "d9",  "d10", "d11", "d12", "d13", "d14", "d15",
            "d16", "d17", "d18", "d19", "d20", "d21", "d22", "d23",
            "d24", "d25", "d26", "d27", "d28", "d29", "d30", "d31"
        };

        if (dRegs.contains(regName))
        {
            uint8_t dRegVal[8];
            size_t outSize;
            const int res = icicle_reg_read_bytes(icicle, toLowerCase(regName).c_str(), dRegVal, 8, &outSize);
            if (res != 0 || outSize != 8)
            {
                LOG_ERROR("Failed to read register " << regName << "!");
                return {.eightByteVal = 0};
            }

            regValue.info.isDoubleReg = true;
            std::memcpy(&regValue.floatVal, dRegVal, 8);
        }
        else
        {
            uint64_t val;
            const int res = icicle_reg_read(icicle, toLowerCase(regName).c_str(), &val);
            if (res != 0)
            {
                LOG_ERROR("Failed to read register " << regName << "!");
            }

            regValue.eightByteVal = val;
        }

        return regValue;
    }
    else if (size == 128)
    {
        return read128BitRegisterValue(regName);
    }
    else if (size == 256)
    {
        return read256BitRegister(regName);
    }

    return {.eightByteVal = 00};
}

registerValueT getRegisterValue(const std::string& regName){
    const auto size = regInfoMap[regName];
    const std::string lowerRegName = toLowerCase(regName);

    if (codeInformation.archIC == IC_ARCH_X86_64 || codeInformation.archIC == IC_ARCH_I386)
    {
        return x86GetRegisterValue(size, lowerRegName);
    }
    else if (codeInformation.archIC == IC_ARCH_ARM || codeInformation.archIC == IC_ARCH_AARCH64)
    {
        return armGetRegisterValue(size, lowerRegName);
    }

    return {.eightByteVal = 00};
}


bool initRegistersToDefinedVals(){
    LOG_INFO("Initialising registers to defined values...");

    for(auto&[name, value]: tempRegisterValueMap){
        const uint64_t intVal = hexStrToInt(value);
        icicle_reg_write(icicle, toLowerCase(name).c_str(), intVal);
    }
    return true;
}

bool write256BitRegisterValue(const std::string& regName, const registerValueT& value)
{
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
    const int result = icicle_reg_write_bytes(icicle, toLowerCase(regName).c_str(), ymmValue, sizeof(ymmValue));
    if (result != 0) {
        LOG_ERROR("Failed to write to YMM register " << regName << ", result=" << result);
        return false;
    }
    return true;
}

bool write128BitRegisterValue(const std::string& regName, const registerValueT& value)
{
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
        const double dValLower = value.info.arrays.doubleArray[1]; // Lower half is index 1
        std::memcpy(&bits_lower, &dValLower, sizeof(double));
        std::memcpy(xmmValue, &bits_lower, 8);

        // Write upper half (index 0) to second 8 bytes
        uint64_t bits_upper;
        const double dValUpper = value.info.arrays.doubleArray[0]; // Upper half is index 0
        std::memcpy(&bits_upper, &dValUpper, sizeof(double));
        std::memcpy(xmmValue + 8, &bits_upper, 8);
    }

    // Write the bytes to the register using icicle_reg_write_bytes
    const int result = icicle_reg_write_bytes(icicle, toLowerCase(regName).c_str(), xmmValue, sizeof(xmmValue));
    if (result != 0) {
        LOG_ERROR("Failed to write to XMM register " << regName << ", result=" << result);
        return false;
    }

    return true;
}

bool x86SetRegisterValue(const std::string& regName, const registerValueT& value)
{
    const auto size = regInfoMap[regName];

    if (size <= 64) {
        return icicle_reg_write(icicle, toLowerCase(regName).c_str(), value.eightByteVal) == 0;
    }
    if (size == 128) {
        return write128BitRegisterValue(regName, value);
    }
    else if (size == 256) {
        return write256BitRegisterValue(regName, value);
    }
    else if (size == 512) {
        LOG_ERROR("Not implemented!");
        return false;
        // // uint8_t zmmValue[64] = {0};
        // //
        // // if (use32BitLanes) {
        // //     // Handle 32-bit lanes (16 float values)
        // //     for (int i = 0; i < 16; i++) {
        // //         uint32_t bits;
        // //         float fval = value.info.arrays.floatArray[i];
        // //         std::memcpy(&bits, &fval, sizeof(float));
        // //
        // //         // Write to the appropriate position in the byte array
        // //         std::memcpy(zmmValue + (i * 4), &bits, 4);
        // //     }
        // // } else {
        // //     // Handle 64-bit lanes (8 double values)
        // //     for (int i = 0; i < 8; i++) {
        // //         uint64_t bits;
        // //         double dval = value.info.arrays.doubleArray[i];
        // //         std::memcpy(&bits, &dval, sizeof(double));
        // //
        // //         // Write to the appropriate position in the byte array
        // //         std::memcpy(zmmValue + (i * 8), &bits, 8);
        // //     }
        // // }
        // //
        // // // Write the bytes to the register using icicle_reg_write_bytes
        // // int result = icicle_reg_write_bytes(icicle, lowerRegName.c_str(), zmmValue, sizeof(zmmValue));
        // // if (result != 0) {
        // //     LOG_ERROR("Failed to write to ZMM register " << regName << ", result=" << result);
        // //     return false;
        // // }
        // return true;
    }

    return false;
}

bool armSetRegisterValue(const std::string& regName, const registerValueT& value)
{
    const auto size = regInfoMap[regName];
    if (size == 32)
    {
        if (vfpRegs.contains(regName))
        {
            uint8_t vfpRegVal[4];
            std::memcpy(vfpRegVal, &value.floatVal, 4);
            const int res = icicle_reg_write_bytes(icicle, toLowerCase(regName).c_str(), vfpRegVal, 4);
            if (res != 0)
            {
                LOG_ERROR("Failed to read vfp register " << regName << "!");
                return false;
            }
        }
        else
        {
            const int res = icicle_reg_write(icicle, toLowerCase(regName).c_str(), value.eightByteVal);
            if (res != 0)
            {
                LOG_ERROR("Failed to read register " << regName << "!");
                return false;
            }
        }

        return true;
    }
    else if (size == 64)
    {


        uint8_t vfpRegVal[8];
        std::memcpy(vfpRegVal, &value.floatVal, 8);
        if (dRegs.contains(regName))
        {
            uint8_t dRegVal[8];
            size_t outSize;
            const int res = icicle_reg_write_bytes(icicle, toLowerCase(regName).c_str(), vfpRegVal, 8);
            if (res != 0)
            {
                LOG_ERROR("Failed to read register " << regName << "!");
                return false;
            }

            return true;
        }
        else
        {
            uint64_t val;
            std::memcpy(&val, &value.eightByteVal, 8);
            const int res = icicle_reg_write(icicle, toLowerCase(regName).c_str(), val);
            if (res != 0)
            {
                LOG_ERROR("Failed to read register " << regName << "!");
                return false;
            }

            return true;
        }
    }
    if (size == 128) {
        return write128BitRegisterValue(regName, value);
    }
    else if (size == 256) {
        return write256BitRegisterValue(regName, value);
    }
    else if (size == 512)
    {
        LOG_ERROR("Not implemented!");
        return false;
    }

    return false;
}

// Function to set register values, handling registers of all sizes
bool setRegisterValue(const std::string& regName, const registerValueT& value) {
    const auto size = regInfoMap[regName];
    const std::string lowerRegName = toLowerCase(regName);

    if (codeInformation.archIC == IC_ARCH_X86_64 || codeInformation.archIC == IC_ARCH_I386)
    {
        return x86SetRegisterValue(lowerRegName, value);
    }
    else if (codeInformation.archIC == IC_ARCH_ARM || codeInformation.archIC == IC_ARCH_AARCH64)
    {
        return armSetRegisterValue(lowerRegName, value);
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
    if (!isDebugReady) {
        LOG_ERROR("Debug mode is not ready");
    }

    const auto vm = icicle_new(codeInformation.archStr, false, true, false, false, false, false, false, false);
    if (!vm)
    {
        printf("Failed to initialize VM\n");
        return nullptr;
    }

    LOG_INFO("Initiation complete...");
    initArch();

    // Initialize BreakpointManager with the new VM instance and callbacks
    auto& bpMgr = getBreakpointManager();
    initBreakpointManagerCallbacks();
    bpMgr.setIcicle(vm);

    // Reapply any existing breakpoints to the new VM
    bpMgr.reapplyBreakpointsToVM();

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

bool updateStack = false;
void stackWriteHook(void* data, uint64_t address, uint8_t size, const uint64_t valueWritten)
{
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
    const auto e = icicle_mem_map(icicle, ENTRY_POINT_ADDRESS, CODE_BUF_SIZE, MemoryProtection::ExecuteReadWrite);
    if (e == -1)
    {
        LOG_ERROR("Failed to map memory for writing code!");
        return false;
    }

    auto k = icicle_mem_write(icicle, ENTRY_POINT_ADDRESS, codeBuf, CODE_BUF_SIZE - 1);
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
    bool alreadyMapped = false;
    size_t regionCount = 0;
    MemRegionInfo* regions = icicle_mem_list_mapped(ic, &regionCount);

    if (regions) {
        for (size_t i = 0; i < regionCount; i++) {
            // Check if this region overlaps with our stack region
            if ((regions[i].address <= STACK_ADDRESS &&
                 regions[i].address + regions[i].size > STACK_ADDRESS) ||
                (regions[i].address >= STACK_ADDRESS &&
                 regions[i].address < STACK_ADDRESS + STACK_SIZE)) {
                LOG_INFO("Stack region already mapped - skipping map operation");
                alreadyMapped = true;
                break;
            }
        }
        if (!alreadyMapped)
        {
            LOG_ERROR("stack regions are not mapped yet!");
        }

        icicle_mem_list_mapped_free(regions, regionCount);
    }

    auto* zeroBuf = static_cast<uint8_t*>(malloc(STACK_SIZE));
    memset(zeroBuf, 0, STACK_SIZE);
    LOG_INFO("Stack mapping if not done already.");
    // Only map if not already mapped
    if (!alreadyMapped) {
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
            const auto s = icicle_mem_read(icicle, STACK_ADDRESS + off, 1, &out);
            icicle_free_buffer(s, 1);
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

    stackArraysZeroed = false;
    LOG_INFO("Stack created successfully!");
    return true;
}

bool resetState(bool reInit){
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
    isEndBreakpointSet = false;

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

    // Reset BreakpointManager state (preserves user breakpoints)
    getBreakpointManager().reset();
    getBreakpointManager().setIcicle(nullptr);

    if (ks != nullptr)
    {
        ks_close(ks);
        ks = nullptr;
    }


    if (!vmSnapshots.empty())
    {
        for (int j = 0; j < vmSnapshots.size(); j++)
        {
            icicle_vm_snapshot_free(vmSnapshots.top());
            vmSnapshots.pop();
        }
        vmSnapshots = {};
    }

    labels.clear();
    emptyLineNumbers.clear();
    addressLineNoMap.clear();
    labelLineNoMapInternal.clear();


    labels = {};
    emptyLineNumbers = {};

    
    labelLineNoMapInternal = {};

    if (reInit)
    {
        if (getBytes(selectedFile).empty()) {
            criticalSection.unlock();
            return false;
        }
    }

    for (const auto &key: registerValueMap | std::views::keys){
        registerValueMap[key] = "0x00";
    }

    stackArraysZeroed = false;

    if (codeBuf)
    {
        free(codeBuf);
    }

    LOG_DEBUG("State reset completed!");
    criticalSection.unlock();
    return true;
}

uint64_t lineNoToAddress(const uint64_t& lineNo)
{
    return lineNoToAddressCallback(lineNo);
}

uint64_t addressToLineNo(const uint64_t& address)
{
    return addressToLineNoCallback(address);
}

bool isSilentBreakpoint(const uint64_t& lineNo)
{
    // Delegate to BreakpointManager which encapsulates the logic
    return getBreakpointManager().isSilentBreakpoint(lineNo);
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
    auto& bpMgr = getBreakpointManager();

    if (silent) {
        // Silent breakpoints are not tracked in user breakpoint list
        // lineNo is 0-based here, add 1 for internal use
        return bpMgr.addSilentBreakpoint(lineNo + 1);
    } else {
        // User breakpoints are tracked and highlighted
        // lineNo is 0-based, addUserBreakpoint expects 1-based
        return bpMgr.addUserBreakpoint(lineNo + 1);
    }
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

    if (codeBuf){
        free(codeBuf);
        codeBuf = nullptr;
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
    updateRegs(true);
    return true;
}