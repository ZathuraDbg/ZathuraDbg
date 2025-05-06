#include "assembler.hpp"
#include "../interpreter/interpreter.hpp"
#include <capstone/capstone.h>

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

// why does the instruction work but all registers have the value of the stack?
uint64_t lastInstructionLineNo = 0;
void initInsSizeInfoMap(){
    LOG_INFO("Updating instruction sizes info map...");
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
            auto start = std::find_if_not(instructionStr.begin(), instructionStr.end(), ::isspace);
            auto end = std::find_if_not(instructionStr.rbegin(), instructionStr.rend(), ::isspace).base();
            std::size_t length = std::distance(start, end);
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

void updateInstructionSizes(const std::string& compiledAsm){
    LOG_INFO("Updating instruction sizes...");
    if (codeInformation.archIC == IC_ARCH_AARCH64)
    {
        for (int i = 0; i < totalInstructions; i++)
        {
            instructionSizes.push_back(4);
        }
        return;
    }

    csh handle;
    cs_insn *instruction;

    if (cs_open(codeInformation.archCS, codeInformation.modeCS, &handle) != CS_ERR_OK)
        return;

    const size_t count = cs_disasm(handle, reinterpret_cast<const uint8_t *>(compiledAsm.c_str()), compiledAsm.length(),
                                   ENTRY_POINT_ADDRESS, 0, &instruction);
    if (count > 0) {
        for (size_t j = 0; j < count; j++) {
            instructionSizes.push_back(instruction[j].size);
        }

        cs_free(instruction, count);
    } else {
        LOG_ERROR("Failed to get instruction sizes with capstone. Exiting...");
        tinyfd_messageBox("Unable to run the given code!\n",  "Please check the logs and create an issue on GitHub if the issue persists", "ok", "error", 0);
    }

    cs_close(&handle);
}

std::string getBytes(const std::string& fileName){
    LOG_DEBUG("Getting bytes from the file: " << fileName);

    std::ifstream asmFile(fileName);

    if (!asmFile.is_open()){
        LOG_ERROR("File can not be read: getBytes(" << fileName << ")");
        tinyfd_messageBox("File read error!", "Asm file can't be read!", "ok", "error", 0);
        return "";
    }

    assembly << asmFile.rdbuf();
    asmFile.close();

    const keystoneSettings ksSettings = {.arch = codeInformation.archKS, .mode = codeInformation.modeKS, .optionType = KS_OPT_SYNTAX, .optionValue=codeInformation.syntax};
    auto [bytes, size] = assemble(assembly.str(), ksSettings);

    if (size == 0 && bytes.empty()) {
        LOG_ERROR("Assembly failed, skipping instruction size and map initialization.");
        return "";
    }

    if (codeInformation.archIC != IC_ARCH_AARCH64)
    {
        updateInstructionSizes(bytes);
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