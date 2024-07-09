#include "windows.hpp"
#include <cstring>
bool codeHasRun = false;
bool stepClickedOnce = false;

tsl::ordered_map<std::string, std::string> registerValueMap = {{"RIP", "0x00"}, {"RSP", "0x00"}, {"RBP", "0x00"},{"RAX", "0x00"}, {"RBX", "0x00"}, {"RCX", "0x00"}, {"RDX", "0x00"},
                                                               {"RSI", "0x00"}, {"RDI", "0x00"}, {"R8", "0x00"}, {"R9", "0x00"}, {"R10", "0x00"}, {"R11", "0x00"}, {"R12", "0x00"},
                                                               {"R13", "0x00"}, {"R14", "0x00"}, {"R15", "0x00"}, {"CS", "0x00"}, {"DS", "0x00"}, {"ES", "0x00"}, {"FS", "0x00"}, {"GS", "0x00"}, {"SS", "0x00"}};
std::unordered_map<std::string, std::string> tempRegisterValueMap =  {};

void updateRegs(bool useTempContext){
    std::stringstream hex;
    std::pair<bool, uint64_t> val;

    for (const auto& [name, value]: registerValueMap) {
        val = useTempContext ? getRegister(toLowerCase(name), true) : getRegister(toLowerCase(name));
        auto const [isRegisterValid, registerValue] = val;

        hex << "0x";
        if (isRegisterValid){
            if (registerValue == 0){
                hex << std::hex << "00";
            }
            else{
                hex << std::hex << registerValue;
            }
        }
        else {
            hex << "00";
        }

        registerValueMap[name] = hex.str();
        hex.str("");
        hex.clear();
    }
}

std::vector<std::string> parseRegisters(std::string registerString){
    std::vector<std::string> registers = {};
    uint16_t index = 0;

    size_t registerCount = std::count(registerString.begin(), registerString.end(), ',') + 1;
    // the string only contains one register
    if (registerCount == 0){
        registers.emplace_back(registerString);
        return registers;
    }

    registers.resize(registerCount);

    for (auto c: registerString){
        if (c != ',' && c != ' '){
            registers[index] += c;
        }

        if (c == ','){
            index++;
        }
    }
    return registers;
}

static int checkHexCharsCallback(ImGuiInputTextCallbackData* data) {
    std::string input(data->Buf, data->BufTextLen);
    std::string filteredString;

    if (input.starts_with("0x")){
        filteredString += "0x";
    }

    for (int i = 2; i < input.length(); i++){
        if ((input[i] >= '0' && input[i] <= '9') || (input[i] >= 'A' && input[i] <= 'F') || (input[i] >= 'a' && input[i] <= 'f')) {
            filteredString += input[i];
        }
    }

    strncpy(data->Buf, filteredString.c_str(), filteredString.length());
    return 0;
}

uint64_t hexStrToInt(const std::string& val){
    uint64_t ret;
    bool exceptionFired = false;
    std::string exception;

    try {
        ret = std::stoul(val, nullptr, 16);
    }
    catch (const std::exception& ex){
        exceptionFired = true;
        exception = ex.what();
        LOG_ERROR("Exception during stoi(): " << exception);
        return 0;
    }

    return ret;
};


void registerWindow() {
    if (codeHasRun){
        if (tempContext!= nullptr){
            updateRegs(true);
        }
        else{
            updateRegs();
        }
    }

    auto io = ImGui::GetIO();
    ImGui::PushFont(io.Fonts->Fonts[3]);

    if (ImGui::BeginTable("RegistersTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Register", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Register", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        int index = 0;
        for (auto it = registerValueMap.begin(); it != registerValueMap.end(); ++index) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            float textHeight = ImGui::GetTextLineHeight();
            float frameHeight = ImGui::GetFrameHeight();
            float spacing = (frameHeight - textHeight) / 2.0f;
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + spacing);
            ImGui::Text("%s", it->first.c_str());

            ImGui::TableSetColumnIndex(1);
            static char value1[64] = {};
            strncpy(value1, it->second.c_str(), sizeof(value1) - 1);
            value1[sizeof(value1) - 1] = '\0';

            ImGui::PushID(index * 2);
            ImGui::SetNextItemWidth(-FLT_MIN);
            if (ImGui::InputText(("##value1" + std::to_string(index)).c_str(), value1, IM_ARRAYSIZE(value1), ImGuiInputTextFlags_CharsNoBlank, checkHexCharsCallback)) {
                if ((strlen(value1) != 0)) {
                    uint64_t temp = hexStrToInt(value1);

                    if (strncmp(value1, "0x", 2) != 0) {
                        registerValueMap[it->first] = "0x";
                        registerValueMap[it->first].append(value1);

                    } else {
                        registerValueMap[it->first] = value1;
                    }

                    LOG_DEBUG("Register: " << it->first << "\n\tValue: " << value1 << "; after hexconv: " << temp);

                    if (codeHasRun)
                    {
                        uc_reg_write(uc, regNameToConstant(it->first), &temp);
                        uc_context_save(uc, context);
                    }
                    else{
                        tempRegisterValueMap[it->first] = value1;
                    }
                }
            }
            ImGui::PopID();

            ++it;
            if (it == registerValueMap.end()) break;

            ImGui::TableSetColumnIndex(2);
            ImGui::Text("%s", it->first.c_str());

            ImGui::TableSetColumnIndex(3);
            static char value2[64] = {};
            strncpy(value2, it->second.c_str(), sizeof(value2) - 1);
            value2[sizeof(value2) - 1] = '\0';

            ImGui::PushID(index * 2 + 1);
            ImGui::SetNextItemWidth(-FLT_MIN);
            if (ImGui::InputText(("##value2" + std::to_string(index)).c_str(), value2, IM_ARRAYSIZE(value2), ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_CharsUppercase | ImGuiInputTextFlags_CharsNoBlank)) {
                if ((strlen(value2) != 0)) {

                if (strncmp(value2, "0x", 2) != 0) {
                    registerValueMap[it->first] = "0x";
                    registerValueMap[it->first].append(value2);
                } else {
                    registerValueMap[it->first] = value2;
                }

                uint64_t temp;
                temp = hexStrToInt(value2);

                LOG_DEBUG("Register: " << it->first << "; Value: " << value2 << "; after hexconv: " << temp);
                    if (codeHasRun)
                    {
                        uc_reg_write(uc, regNameToConstant(it->first), &temp);
                        uc_context_save(uc, context);
                    }
                    else{
                        tempRegisterValueMap[it->first] = value2;
                    }
            }
        }
            ImGui::PopID();
            ++it;
            if (it == registerValueMap.end()) break;
        }

        ImGui::EndTable();
    }

    const float footer_height_to_reserve = ImGui::GetStyle().ItemSpacing.y + ImGui::GetFrameHeightWithSpacing();

    ImGui::BeginChild("ScrollingRegion", ImVec2(0, -footer_height_to_reserve), false, ImGuiWindowFlags_None);
    ImGui::EndChild();

    std::string registerString;
    char input[500] = {};

    ImGui::PushID(&input);
    ImGui::Text("Toggle registers: ");
    ImGui::SameLine();

    if (ImGui::InputText("##registerInput", input, IM_ARRAYSIZE(input), ImGuiInputTextFlags_EnterReturnsTrue)) {
        registerString += toLowerCase(input);
        LOG_DEBUG("Request to add the register: " << input);
    }

    if (!registerString.empty()) {
        auto regs = parseRegisters(registerString);
        for (auto& reg : regs) {
            auto regInfo = getRegister(reg);
            if (regInfo.first) {
                auto regValue= std::to_string(regInfo.second);
                LOG_DEBUG("Adding the register " << reg);
                reg = toUpperCase(reg);

                if (x86RegInfoMap.count(reg) == 0){
                    continue;
                }

//              remove the register if it already exists
                if (registerValueMap.count(reg) != 0){
                    registerValueMap.erase(reg);
                    continue;
                }

                if (regValue == "0"){
                    regValue = "0x00";
                }
                registerValueMap[reg] = regValue;
            } else {
                LOG_ERROR("Unable to get the register: " << reg);
            }
        }
    }

    ImGui::PopID();
    ImGui::PopFont();
}