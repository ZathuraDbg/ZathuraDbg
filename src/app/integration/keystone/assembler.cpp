#include "assembler.hpp"
#include "../interpreter/interpreter.hpp"
#include <capstone/capstone.h>

ks_engine *ks = nullptr;
uint64_t codeFinalLen = 0;
uint64_t totalInstructions = 0;
std::stringstream assembly;
std::vector<std::string> labels;

std::map<std::string, std::string> addressLineNoMap{};
std::map<std::string, int> labelLineNoMapInternal{};
std::vector<uint16_t> instructionSizes{};

std::pair<std::string, std::size_t> assemble(const std::string& assemblyString, const keystoneSettings& ksSettings) {
    LOG_DEBUG("Assembling:\n" << assemblyString);
    ks_err err;
    size_t size;
    size_t count;
    unsigned char *encode;
    std::pair<std::string, std::size_t> assembled;

    if (ks == nullptr){
        err = ks_open(ksSettings.arch, ksSettings.mode, &ks);

        if (err != KS_ERR_OK) {
            std::cerr << "ERROR: Failed to initialize Keystone engine: " << ks_strerror(err) << std::endl;
            tinyfd_messageBox("ERROR!","Failed to initialize Keystone engine!", "ok", "error", 0);
            return {"", 0};
        }

        if (ksSettings.optionType){
            ks_option(ks, ksSettings.optionType, ksSettings.optionValue);
        }

        LOG_DEBUG("Keystone object initialised.");
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

    assembled = {std::string((const char*)encode, size), size};

    ks_free(encode);
    ks_close(ks);
    ks = nullptr;

    codeFinalLen = size;
    LOG_DEBUG("Assembled: " << size << " bytes");
    return assembled;
}


uint lastInstructionLineNo = 0;
void initInsSizeInfoMap(){
    std::string instructionStr;

    uint lineNo = 1;
    uint16_t count = 0;
    uint64_t currentAddr = ENTRY_POINT_ADDRESS;
    uint64_t insCount = 0;
    bool foundFirstLabel = false;

    while (std::getline(assembly, instructionStr, '\n')) {
        if (instructionStr.contains(":")){
            instructionStr.erase(std::remove_if(instructionStr.begin(), instructionStr.end(), ::isspace), instructionStr.end());
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

                        labelLineNoMapInternal.insert({instructionStr.substr(0, instructionStr.find_first_of(':')), lineNo});
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
                    labelLineNoMapInternal.insert({instructionStr.substr(0, instructionStr.find_first_of(':')), lineNo});
                    labels.push_back(instructionStr.substr(0, instructionStr.find_first_of(':')));
                    lineNo++;
                    continue;
                }
            }
        }
        else if (instructionStr.empty()){
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

        if (auto idx = instructionStr.find_first_of(' '); idx != std::string::npos){
            instructionStr = instructionStr.substr(0, idx);
        }

        if (instructionStr.contains(";")){
            lineNo++;
            continue;
        }

        instructionStr = toUpperCase(instructionStr);

//       if it's valid instruction
        if (std::find(x86Instructions.begin(), x86Instructions.end(), instructionStr) != x86Instructions.end()){
            addressLineNoMap.insert({std::to_string(currentAddr), std::to_string(lineNo)});
            currentAddr += instructionSizes[count];
            count++;
        }
        lineNo++;
    }
    totalInstructions = count;
    LOG_DEBUG("Total instructions to execute: " << totalInstructions);
}

void updateInstructionSizes(const std::string& compiledAsm){
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(codeInformation.archCS, codeInformation.modeCS, &handle) != CS_ERR_OK)
        return;

    count = cs_disasm(handle, reinterpret_cast<const uint8_t *>(compiledAsm.c_str()), compiledAsm.length(), ENTRY_POINT_ADDRESS, 0, &insn);
    if (count > 0) {
        size_t j;
        size_t line = 1;
        for (j = 0; j < count; j++) {
            instructionSizes.push_back(insn[j].size);
        }

        cs_free(insn, count);
    } else
        printf("ERROR: Failed to updateInstructionSizes given code!\n");

    cs_close(&handle);
}

std::string getBytes(const std::string& fileName){
    LOG_DEBUG("Getting bytes from the file: " << fileName);

    std::ifstream asmFile(fileName);

    if (!asmFile.is_open()){
        LOG_ERROR("Asm file can not be read: getBytes(" << fileName << ")");
        tinyfd_messageBox("File read error!", "Asm file can't be read!", "ok", "error", 0);
        return "";
    }

    assembly << asmFile.rdbuf();
    asmFile.close();

    keystoneSettings ksSettings = {.arch = codeInformation.archKS, .mode = codeInformation.modeKS, .optionType = KS_OPT_SYNTAX, .optionValue=codeInformation.syntax};
    auto [bytes, size] = assemble(assembly.str(), ksSettings);

    updateInstructionSizes(bytes);
    initInsSizeInfoMap();
    LOG_DEBUG("Got bytes, now hexlifying.");
    return hexlify({bytes.data(), size});
}

std::string getBytes(std::stringstream &assemblyStream){
    keystoneSettings ksSettings = {.arch = codeInformation.archKS, .mode = codeInformation.modeKS, .optionType = KS_OPT_SYNTAX, .optionValue=codeInformation.syntax};
    auto [bytes, size] = assemble(assemblyStream.str(), ksSettings);

    LOG_DEBUG("Got bytes, now hexlifying.");
    return hexlify({bytes.data(), size});
}