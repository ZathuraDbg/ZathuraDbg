#include "assembler.hpp"
#include "../interpreter/interpreter.hpp"
#include <capstone/capstone.h>
#include <algorithm>

ks_engine *ks = nullptr;
uint64_t codeFinalLen = 0;
uint64_t totalInstructions = 0;
std::stringstream assembly;
std::vector<std::string> labels;
uint64_t tempTotalIns = 0;

std::unordered_map<uint64_t, uint64_t> addressLineNoMap{};
std::map<std::string, int> labelLineNoMapInternal{};

std::vector<uint16_t> instructionSizes{};
std::vector<uint64_t> emptyLineNumbers{};


std::pair<std::string, std::size_t> assemble(const std::string& assemblyString, const keystoneSettings& ksSettings) {
    LOG_INFO("Assembling code...");
    ks_err err;
    size_t size;
    size_t count;
    unsigned char *encode;

    if (ks == nullptr){
        err = ks_open(ksSettings.arch, ksSettings.mode, &ks);

        if (err != KS_ERR_OK) {
            tinyfd_messageBox("ERROR!","Failed to initialize Keystone engine!", "ok", "error", 0);
            return {"", 0};
        }

        if (ksSettings.optionType && codeInformation.archIC == IC_ARCH_X86_64){
            ks_option(ks, ksSettings.optionType, ksSettings.optionValue);
        }

        LOG_INFO("Keystone object initialised.");
    }
    else{
        LOG_DEBUG("Keystone object already exists. Using that instead.");
    }

    if (ks_asm(ks, assemblyString.data(), 0, &encode, &size, &count)) {
        err = ks_errno(ks);
        const std::string error(ks_strerror(err));
        if (err == KS_ERR_ASM_INVALIDOPERAND){
            LOG_ERROR("Wrong architecture error!: " << error);
            tinyfd_messageBox("Assembly syntax error!", "The code does not belong to the currently selected architecture!"
                                    "\nPlease change the architecture in the settings.", "ok", "error", 0);
        }
        else if (err >= KS_ERR_ASM){
            LOG_ERROR("Assembly syntax error: " << error);
            tinyfd_messageBox("Assembly syntax error!", error.c_str(), "ok", "error", 0);
        }

        LOG_ERROR(error);
        ks_close(ks);
        ks = nullptr;
        return {"", 0};
    }
    else {
        LOG_INFO("Assembly compiled successfully.");
    }

    std::pair<std::string, std::size_t> assembled = {std::string(reinterpret_cast<const char *>(encode), size), size};
    ks_free(encode);

    codeFinalLen = size;
    LOG_DEBUG("Assembled: " << size << " bytes");
    return assembled;
}

bool isValidInstruction(ks_engine* ksEngine, const char* instruction) {
    size_t size{};
    size_t count{};
    unsigned char *encode = nullptr;
    ks_err err;
    bool engineCreatedInternally = false;

    if (ksEngine == nullptr)
    {
        err = ks_open(codeInformation.archKS, codeInformation.modeKS, &ksEngine);
        if (err != KS_ERR_OK)
        {
            LOG_ERROR("Failed to initialize Keystone engine: " << ks_strerror(err));
            return false;
        }
        engineCreatedInternally = true;
    }

    const auto status = ks_asm(ksEngine, instruction, 0, &encode, &size, &count);
    bool result = false;

    if (status == 0 && size != 0)
    {
        ks_free(encode);
        result = true;
    }
    else if (status == -1)
    {
        if (encode)
        {
            ks_free(encode);
        }
        err = ks_errno(ksEngine);
        std::string error(ks_strerror(err));
        if (err == KS_ERR_ASM_SYMBOL_MISSING || err == KS_ERR_OK)
        {
            result = true;
        }
    }

    if (engineCreatedInternally) {
        ks_close(ksEngine);
    }

    return result;
}

uint64_t lastInstructionLineNo = 0;
void initInsSizeInfoMap(){
    LOG_INFO("Updating instruction sizes info map...");
    
    if (instructionSizes.empty() && codeInformation.archIC != IC_ARCH_AARCH64) {
        LOG_ERROR("instructionSizes is empty! Cannot initialize instruction size info map.");
        return;
    }
    
    std::string instructionStr;

    uint64_t lineNo = 1;
    uint16_t count = 0;
    uint64_t currentAddr = ENTRY_POINT_ADDRESS;
    uint64_t insCount = 0;
    bool foundFirstLabel = false;
    std::string line{};

    // TODO: Scan for multiline comments and ignore them
    while (std::getline(assembly, instructionStr, '\n')) {


        if (instructionStr.contains(';'))
            instructionStr = instructionStr.substr(0, instructionStr.find_first_of(';')); // Clearing out the comments
        

        {
            const auto start = std::ranges::find_if_not(instructionStr, ::isspace);
            const auto end = std::find_if_not(instructionStr.rbegin(), instructionStr.rend(), ::isspace).base();
            const std::size_t length = std::distance(start, end);
            instructionStr = instructionStr.substr(std::distance(instructionStr.begin(), start), length); // Trimmed whitespaces from both left and right

        }

        if (instructionStr.empty()){
            emptyLineNumbers.push_back(lineNo);
            lineNo++;
            continue;
        }


         if (instructionStr.contains(":")){
            instructionStr.erase(std::ranges::remove_if(instructionStr, ::isspace).begin(), instructionStr.end());

            if (instructionStr.ends_with(":")){
                std::string labelStr = instructionStr.substr(0, instructionStr.find_first_of(':'));
                labelLineNoMapInternal.insert({labelStr, lineNo});
                labels.push_back(labelStr);
                lineNo++;
                continue;

            }
        }


        line = instructionStr;


        instructionStr = toUpperCase(instructionStr);


        if (isValidInstruction(ks, line.c_str()) || (codeInformation.archIC == IC_ARCH_AARCH64 && instructionStr.contains('.'))){
             if (labels.size() <= 1)
                lastInstructionLineNo = lineNo;

            addressLineNoMap.insert({currentAddr, lineNo});
            if (codeInformation.archIC == IC_ARCH_AARCH64)
                currentAddr += 4; // every instruction in aarch64 is 4 bytes long
            else
            {
                if (count < instructionSizes.size()) {
                    currentAddr += instructionSizes[count];
                } else {
                    std::cerr << "instructionSizes out-of-bounds: count = " << count
                              << ", instructionSizes.size() = " << instructionSizes.size()
                              << ", lineNo = " << lineNo
                              << ", instruction = " << line << "\n";
                    std::abort();
                }
            }

            count++;
        }
        else
            emptyLineNumbers.push_back(lineNo);
        
        lineNo++;
    }


    totalInstructions = count;
    LOG_INFO("Updated to instruction size information map.");
    LOG_DEBUG("Total instructions to execute: " << totalInstructions);
}

uint64_t countValidInstructions(std::stringstream& asmStream){
    LOG_INFO("Counting valid instructions...");
    std::string instructionStr;
    uint16_t count = 0;

    while (std::getline(asmStream, instructionStr, '\n')) {

        if (instructionStr.contains(';'))
            instructionStr = instructionStr.substr(0, instructionStr.find_first_of(';')); // Clearing out the comments
        
        {
            auto start = std::find_if_not(instructionStr.begin(), instructionStr.end(), ::isspace);
            auto end = std::find_if_not(instructionStr.rbegin(), instructionStr.rend(), ::isspace).base();
            std::size_t length = std::distance(start, end);
            instructionStr = instructionStr.substr(std::distance(instructionStr.begin(), start), length); // Trimmed whitespaces from both left and right

        }

        if (instructionStr.empty())
            continue;

        instructionStr = toUpperCase(instructionStr);
        const auto spaceIt = instructionStr.find_first_of(' ');
        if (spaceIt != std::string::npos){
            instructionStr = instructionStr.substr(0, spaceIt);
        }

        if (std::ranges::find(archInstructions, instructionStr) != archInstructions.end()){
            count++;
        }
    }

    LOG_DEBUG("Total valid instructions : " << count);
    return count;
}

bool updateInstructionSizes(const std::string& compiledAsm){
    LOG_INFO("Updating instruction sizes...");
    instructionSizes.clear();  // Clear previous sizes
    
    if (codeInformation.archIC == IC_ARCH_AARCH64)
    {
        for (int i = 0; i < totalInstructions; i++)
        {
            instructionSizes.push_back(4);
        }
        return true;
    }

    csh handle;
    cs_insn *instruction;

    LOG_INFO("Capstone arch: " << codeInformation.archCS << ", mode: " << codeInformation.modeCS);
    LOG_INFO("Compiled assembly size: " << compiledAsm.length() << " bytes");
    LOG_INFO("First 20 bytes: ");
    for (size_t i = 0; i < std::min(compiledAsm.length(), (size_t)20); i++) {
        LOG_INFO("  Byte[" << i << "]: 0x" << std::hex << (unsigned char)compiledAsm[i] << std::dec);
    }
    
    if (cs_open(codeInformation.archCS, codeInformation.modeCS, &handle) != CS_ERR_OK) {
        LOG_ERROR("Failed to open capstone handle!");
        return false;
    }

    LOG_INFO("Capstone handle opened successfully");
    
    const size_t count = cs_disasm(handle, reinterpret_cast<const uint8_t *>(compiledAsm.c_str()), compiledAsm.length(),
                                   ENTRY_POINT_ADDRESS, 0, &instruction);
    LOG_INFO("Capstone disassembled " << count << " instructions");
    
    if (count > 0) {
        for (size_t j = 0; j < count; j++) {
            instructionSizes.push_back(instruction[j].size);
            LOG_INFO("  Instruction[" << j << "]: " << instruction[j].mnemonic << " - " << (int)instruction[j].size << " bytes");
        }

        cs_free(instruction, count);
        cs_close(&handle);
        LOG_INFO("Successfully updated instruction sizes. Total: " << instructionSizes.size());
        return true;
    } else {
        LOG_ERROR("FAILED: Capstone returned 0 instructions!");
        LOG_ERROR("  - Architecture: " << codeInformation.archCS);
        LOG_ERROR("  - Mode: " << codeInformation.modeCS);
        LOG_ERROR("  - Entry point: 0x" << std::hex << ENTRY_POINT_ADDRESS);
        LOG_ERROR("  - Data size: " << std::dec << compiledAsm.length());
        tinyfd_messageBox("Unable to run the given code!\n",  "Please check the logs and create an issue on GitHub if the issue persists", "ok", "error", 0);
        cs_close(&handle);
        return false;
    }
}

std::string getBytes(const std::string& fileName){
    LOG_DEBUG("Getting bytes from the file: " << fileName);

    std::ifstream asmFile(fileName);

    if (!asmFile.is_open()){
        LOG_ERROR("File can not be read: getBytes(" << fileName << ")");
        tinyfd_messageBox("File read error!", "Asm file can't be read!", "ok", "error", 0);
        return "";
    }
    assembly.clear();
    assembly.str("");
    assembly = {};
    assembly << asmFile.rdbuf();
    asmFile.close();

    const keystoneSettings ksSettings = {.arch = codeInformation.archKS, .mode = codeInformation.modeKS, .optionType = KS_OPT_SYNTAX, .optionValue=codeInformation.syntax};
    
    std::string asmStr = assembly.str();
    LOG_DEBUG("Assembly string length: " << asmStr.length());
    LOG_DEBUG("First 100 chars: [" << asmStr.substr(0, 100) << "]");
    
    auto [bytes, size] = assemble(asmStr, ksSettings);

    if (size == 0 && bytes.empty()) {
        LOG_ERROR("Assembly failed, skipping instruction size and map initialization.");
        return "";
    }
    
    LOG_DEBUG("Assembled bytes length: " << bytes.length());
    LOG_DEBUG("Assembled size: " << size);

    if (codeInformation.archIC != IC_ARCH_AARCH64)
    {
        if (!updateInstructionSizes(bytes)) {
            LOG_ERROR("Failed to update instruction sizes, aborting.");
            return "";
        }
    }

    initInsSizeInfoMap();
    LOG_INFO("Got bytes, now hexlifying...");

    if (ks)
    {
         ks_close(ks);
         ks = nullptr;
    }
    return hexlify({bytes.data(), size});
}

std::string getBytes(const std::stringstream &assembly){
    const keystoneSettings ksSettings = {.arch = codeInformation.archKS, .mode = codeInformation.modeKS, .optionType = KS_OPT_SYNTAX, .optionValue=codeInformation.syntax};
    auto [bytes, size] = assemble(assembly.str(), ksSettings);
    LOG_INFO("Got bytes, now hexlifying...");
    if (ks)
    {
         ks_close(ks);
         ks = nullptr;
    }
    return hexlify({bytes.data(), size});
}