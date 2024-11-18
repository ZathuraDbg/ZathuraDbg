#include "assembler.hpp"
#include "../interpreter/interpreter.hpp"
#include <capstone/capstone.h>

ks_engine *ks = nullptr;
uint64_t codeFinalLen = 0;
uint64_t totalInstructions = 0;
std::stringstream assembly;
std::vector<std::string> labels;
uint64_t tempTotalIns = 0;

std::map<std::string, std::string> addressLineNoMap{};
std::map<std::string, int> labelLineNoMapInternal{};
tsl::ordered_map<std::string, std::pair<uint, uint>> labelLineNoRange{};
std::vector<uint16_t> instructionSizes{};
std::vector<uint> emptyLineNumbers{};

std::pair<std::string, std::size_t> assemble(const std::string& assemblyString, const keystoneSettings& ksSettings) {
    LOG_INFO("Assembling code...");
    ks_err err;
    size_t size;
    size_t count;
    unsigned char *encode;

    if (ks == nullptr){
        LOG_INFO("Keystone object doesn't exists, creating...");
        err = ks_open(ksSettings.arch, ksSettings.mode, &ks);

        if (err != KS_ERR_OK) {
            LOG_ERROR("Failed to initialize Keystone engine: " << ks_strerror(err));
            tinyfd_messageBox("ERROR!","Failed to initialize Keystone engine!", "ok", "error", 0);
            return {"", 0};
        }

        if (ksSettings.optionType){
            ks_option(ks, ksSettings.optionType, ksSettings.optionValue);
        }

        LOG_INFO("Keystone object initialised.");
    }
    else{
        LOG_DEBUG("Keystone object already exists. Using that instead.");
    }

    if (ks_asm(ks, assemblyString.data(), 0, &encode, &size, &count)) {
        err = ks_errno(ks);
        std::string error(ks_strerror(err));
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
    ks_close(ks);
    ks = nullptr;

    codeFinalLen = size;
    LOG_DEBUG("Assembled: " << size << " bytes");
    return assembled;
}

uint lastInstructionLineNo = 0;
void initInsSizeInfoMap(){
    LOG_INFO("Upding instruction sizes info map...");
    std::string instructionStr;

    uint lineNo = 1;
    uint16_t count = 0;
    uint64_t currentAddr = ENTRY_POINT_ADDRESS;
    uint64_t insCount = 0;
    bool foundFirstLabel = false;

    // TODO: Scan for multiline comments and ignore them
    while (std::getline(assembly, instructionStr, '\n')) {
        if (instructionStr.contains(":")){
            instructionStr.erase(std::ranges::remove_if(instructionStr, ::isspace).begin(), instructionStr.end());
            if (instructionStr.ends_with(":")){
                if (instructionStr.contains(';')){
                    if (instructionStr.find_first_of(';') > instructionStr.find_last_of(':')){
                        if (labels.empty()){
                            foundFirstLabel = true;
                        }
                        else if (foundFirstLabel){
                            lastInstructionLineNo = std::atoi(std::prev(addressLineNoMap.end())->second.data());
                            foundFirstLabel = false;
                        }
                        if (!labelLineNoRange.empty()) {
                            labelLineNoRange[labelLineNoRange.back().first].second = strtol(std::prev(addressLineNoMap.end())->second.data(), nullptr, 10);
                        }

                        labelLineNoMapInternal.insert({instructionStr.substr(0, instructionStr.find_first_of(':')), lineNo});
                        labelLineNoRange.insert({instructionStr.substr(0, instructionStr.find_first_of(':')), {lineNo, 0}});
                        labels.push_back(instructionStr.substr(0, instructionStr.find_first_of(':')));
                    }
                }
                else{
                    if (labels.empty()){
                        foundFirstLabel = true;
                    }
                    else if (foundFirstLabel) {
                        lastInstructionLineNo = std::atoi(std::prev(addressLineNoMap.end())->second.data());
                        foundFirstLabel = false;
                    }

                    if (!labelLineNoRange.empty()) {
                        labelLineNoRange[labelLineNoRange.back().first].second = strtol(std::prev(addressLineNoMap.end())->second.data(), nullptr, 10);
                    }

                    labelLineNoMapInternal.insert({instructionStr.substr(0, instructionStr.find_first_of(':')), lineNo});
                    labelLineNoRange.insert({instructionStr.substr(0, instructionStr.find_first_of(':')), {lineNo, 0}});
                    labels.push_back(instructionStr.substr(0, instructionStr.find_first_of(':')));
                    lineNo++;
                    continue;
                }
            }
        }
        else if (instructionStr.empty()){
            emptyLineNumbers.push_back(lineNo);
            lineNo++;
            continue;
        }

        if (instructionStr.starts_with("\t")){
            auto idx = instructionStr.find_first_not_of('\t');
            if (idx != std::string::npos){
                instructionStr = instructionStr.substr(idx);
            }
        }
        if (instructionStr.starts_with(" ")){
            auto idx = instructionStr.find_first_not_of(' ');
            if (idx != std::string::npos){
                instructionStr = instructionStr.substr(idx);
            }
        }

        if (const auto idx = instructionStr.find_first_of(' '); idx != std::string::npos){
            instructionStr = instructionStr.substr(0, idx);
        }

        if (instructionStr.contains(";")){
            lineNo++;
            continue;
        }

        instructionStr = toUpperCase(instructionStr);

//       if it's valid instruction
        if (std::ranges::find(x86Instructions, instructionStr) != x86Instructions.end()){
            addressLineNoMap.insert({std::to_string(currentAddr), std::to_string(lineNo)});
            currentAddr += instructionSizes[count];
            count++;
        }
        else {
            emptyLineNumbers.push_back(lineNo);
        }
        lineNo++;
    }

    if (!labelLineNoRange.empty() && (!addressLineNoMap.empty())) {
        labelLineNoRange[labelLineNoRange.back().first].second = strtol(std::prev(addressLineNoMap.end())->second.data(), nullptr, 10);
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
        if (instructionStr.starts_with("\t")){
            auto idx = instructionStr.find_first_not_of('\t');
            if (idx != std::string::npos){
                instructionStr = instructionStr.substr(idx);
            }
        }
        if (instructionStr.starts_with(" ")){
            auto idx = instructionStr.find_first_not_of(' ');
            if (idx != std::string::npos){
                instructionStr = instructionStr.substr(idx);
            }
        }

        if (instructionStr.starts_with(" ") || instructionStr.starts_with("\t")){
            instructionStr = instructionStr.substr(1);
        }

        if (instructionStr.empty()){
            continue;
        }

        if (instructionStr.contains(";")){
            continue;
        }

        instructionStr = toUpperCase(instructionStr);
        auto spaceIt = instructionStr.find_first_of(' ');
        if (spaceIt != std::string::npos){
            instructionStr = instructionStr.substr(0, spaceIt);
        }

        if (std::ranges::find(x86Instructions, instructionStr) != x86Instructions.end()){
            count++;
        }
    }

    LOG_DEBUG("Total valid instructions : " << count);
    return count;
}

void updateInstructionSizes(const std::string& compiledAsm){
    LOG_INFO("Updating instruction sizes...");
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

    keystoneSettings ksSettings = {.arch = codeInformation.archKS, .mode = codeInformation.modeKS, .optionType = KS_OPT_SYNTAX, .optionValue=codeInformation.syntax};
    auto [bytes, size] = assemble(assembly.str(), ksSettings);

    if (size == 0 && bytes.empty()) {
        return "";
    }

    updateInstructionSizes(bytes);
    initInsSizeInfoMap();
    LOG_INFO("Got bytes, now hexlifying...");
    return hexlify({bytes.data(), size});
}

std::string getBytes(std::stringstream &assembly){
    const keystoneSettings ksSettings = {.arch = codeInformation.archKS, .mode = codeInformation.modeKS, .optionType = KS_OPT_SYNTAX, .optionValue=codeInformation.syntax};
    auto [bytes, size] = assemble(assembly.str(), ksSettings);
    LOG_INFO("Got bytes, now hexlifying...");
    return hexlify({bytes.data(), size});
}