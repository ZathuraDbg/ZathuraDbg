#include "interpreter.hpp"

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

registerValueT getRegisterValue(const std::string& regName) {
    const auto size = regInfoMap[regName];
    const std::string lowerRegName = toLowerCase(regName);
    const bool isX86 = (codeInformation.archIC == IC_ARCH_X86_64 || codeInformation.archIC == IC_ARCH_I386);

    // 128-bit and 256-bit: same for all archs
    if (size == 128) return read128BitRegisterValue(lowerRegName);
    if (size == 256) return read256BitRegister(lowerRegName);
    if (size == 512) {
        LOG_WARNING("512-bit registers not yet supported by the emulation engine!");
        return {.eightByteVal = 0};
    }

    // ≤64-bit: arch-specific
    if (isX86) {
        uint64_t valTemp64;
        icicle_reg_read(icicle, lowerRegName.c_str(), &valTemp64);
        return {.eightByteVal = valTemp64};
    }

    // ARM/AArch64 ≤64-bit
    registerValueT regValue{};
    if (size == 32 && vfpRegs.contains(lowerRegName)) {
        uint8_t vfpRegVal[4];
        size_t outSize;
        const int res = icicle_reg_read_bytes(icicle, lowerRegName.c_str(), vfpRegVal, 4, &outSize);
        if (res != 0 || outSize != 4) {
            LOG_ERROR("Failed to read vfp register " << regName << "!");
            return {.eightByteVal = 0};
        }
        regValue.info.isFloatReg = true;
        std::memcpy(&regValue.floatVal, vfpRegVal, 4);
        return regValue;
    }
    if (size == 64 && dRegs.contains(lowerRegName)) {
        uint8_t dRegVal[8];
        size_t outSize;
        const int res = icicle_reg_read_bytes(icicle, lowerRegName.c_str(), dRegVal, 8, &outSize);
        if (res != 0 || outSize != 8) {
            LOG_ERROR("Failed to read register " << regName << "!");
            return {.eightByteVal = 0};
        }
        regValue.info.isDoubleReg = true;
        std::memcpy(&regValue.floatVal, dRegVal, 8);
        return regValue;
    }
    // Default ARM register read
    uint64_t val;
    const int res = icicle_reg_read(icicle, lowerRegName.c_str(), &val);
    if (res != 0) {
        LOG_ERROR("Failed to read register " << regName << "!");
        return {.eightByteVal = 0};
    }
    regValue.eightByteVal = val;
    return regValue;
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

bool setRegisterValue(const std::string& regName, const registerValueT& value) {
    const auto size = regInfoMap[regName];
    const std::string lowerRegName = toLowerCase(regName);
    const bool isX86 = (codeInformation.archIC == IC_ARCH_X86_64 || codeInformation.archIC == IC_ARCH_I386);

    // 128-bit and 256-bit: same for all archs
    if (size == 128) return write128BitRegisterValue(regName, value);
    if (size == 256) return write256BitRegisterValue(regName, value);
    if (size == 512) {
        LOG_ERROR("Not implemented!");
        return false;
    }

    // ≤64-bit: arch-specific
    if (isX86) {
        return icicle_reg_write(icicle, lowerRegName.c_str(), value.eightByteVal) == 0;
    }

    // ARM/AArch64 ≤64-bit
    if (size == 32) {
        if (vfpRegs.contains(lowerRegName)) {
            uint8_t vfpRegVal[4];
            std::memcpy(vfpRegVal, &value.floatVal, 4);
            const int res = icicle_reg_write_bytes(icicle, lowerRegName.c_str(), vfpRegVal, 4);
            if (res != 0) {
                LOG_ERROR("Failed to write vfp register " << regName << "!");
                return false;
            }
        } else {
            const int res = icicle_reg_write(icicle, lowerRegName.c_str(), value.eightByteVal);
            if (res != 0) {
                LOG_ERROR("Failed to write register " << regName << "!");
                return false;
            }
        }
        return true;
    }
    if (size == 64) {
        if (dRegs.contains(lowerRegName)) {
            uint8_t dRegVal[8];
            std::memcpy(dRegVal, &value.floatVal, 8);
            const int res = icicle_reg_write_bytes(icicle, lowerRegName.c_str(), dRegVal, 8);
            if (res != 0) {
                LOG_ERROR("Failed to write register " << regName << "!");
                return false;
            }
        } else {
            uint64_t val;
            std::memcpy(&val, &value.eightByteVal, 8);
            const int res = icicle_reg_write(icicle, lowerRegName.c_str(), val);
            if (res != 0) {
                LOG_ERROR("Failed to write register " << regName << "!");
                return false;
            }
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
