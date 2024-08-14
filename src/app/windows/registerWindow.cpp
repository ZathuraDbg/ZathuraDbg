#include "windows.hpp"
#include <cstring>
bool codeHasRun = false;
bool stepClickedOnce = false;
tsl::ordered_map<std::string, std::string> registerValueMap{};

std::unordered_map<std::string, std::string> tempRegisterValueMap =  {};

void initDefaultRegs(){
    for (auto& reg: defaultShownRegs){
        registerValueMap[reg] = "0x00";
    }
}

void updateRegs(bool useTempContext){
    std::stringstream hex;
    std::pair<bool, uint64_t> val;

    for (const auto& [name, value]: registerValueMap) {
        if (!isRegisterValid(toUpperCase(name), codeInformation.mode)){
            continue;
        }
        val = useTempContext ? getRegister(toLowerCase(name), true) : getRegister(toLowerCase(name));
        auto const [isRegValid, registerValue] = val;

        hex << "0x";
        if (isRegValid){
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

int checkHexCharsCallback(ImGuiInputTextCallbackData* data) {
    if (data->BufTextLen < 2){
        return 0;
    }

    std::string input(data->Buf, data->BufTextLen);
    std::string filteredString;

    int i = 0;

    if (toLowerCase(input).starts_with("0x")){
        filteredString += "0x";
        i = 2;
    }
    else{
        input = "0x" + input;
        filteredString += "0x";
        i = 2;
    }

    for (i; i < input.length(); i++){
        if ((input[i] >= '0' && input[i] <= '9') || (input[i] >= 'A' && input[i] <= 'F') || (input[i] >= 'a' && input[i] <= 'f')) {
            filteredString += input[i];
        }
        else{
            filteredString += ' ';
        }
    }

    filteredString.erase(std::remove(filteredString.begin(), filteredString.end(), ' '), filteredString.end());
    data->DeleteChars(0, data->BufTextLen);
    data->InsertChars(0, filteredString.c_str());
    data->BufTextLen = filteredString.length();
    data->CursorPos = data->SelectionStart = data->SelectionEnd = filteredString.length();
    return 0;
}

uint64_t hexStrToInt(const std::string& val){
    uint64_t ret;
    ret = std::strtoul(val.c_str(), nullptr, 16);
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

    if (registerValueMap.empty()){
        initDefaultRegs();
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
        for (auto regValMapInfo = registerValueMap.begin(); regValMapInfo != registerValueMap.end(); ++index) {
            if (!isRegisterValid(toUpperCase(regValMapInfo->first), codeInformation.mode)){
                continue;
            }

            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            float textHeight = ImGui::GetTextLineHeight();
            float frameHeight = ImGui::GetFrameHeight();
            float spacing = (frameHeight - textHeight) / 2.0f;
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + spacing);
            ImGui::Text("%s", regValMapInfo->first.c_str());

            ImGui::TableSetColumnIndex(1);
            static char regValueFirst[64] = {};
            strncpy(regValueFirst, regValMapInfo->second.c_str(), sizeof(regValueFirst) - 1);
            regValueFirst[sizeof(regValueFirst) - 1] = '\0';

            ImGui::PushID(index * 2);
            ImGui::SetNextItemWidth(-FLT_MIN);
            if (ImGui::InputText(("##regValueFirst" + std::to_string(index)).c_str(), regValueFirst, IM_ARRAYSIZE(regValueFirst), ImGuiInputTextFlags_CharsNoBlank | ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CallbackCharFilter, checkHexCharsCallback )) {
                if ((strlen(regValueFirst) != 0)) {
                    uint64_t temp = hexStrToInt(regValueFirst);

                    if (strncmp(regValueFirst, "0x", 2) != 0) {
                        registerValueMap[regValMapInfo->first] = "0x";
                        registerValueMap[regValMapInfo->first].append(regValueFirst);

                    } else {
                        registerValueMap[regValMapInfo->first] = regValueFirst;
                    }

                    if (codeHasRun)
                    {
                        uc_reg_write(uc, regNameToConstant(regValMapInfo->first), &temp);
                        uc_context_save(uc, context);
                    }
                    else{
                        if (regValMapInfo->first == getArchIPStr(codeInformation.mode)){
                            ENTRY_POINT_ADDRESS = strtoul(regValueFirst, nullptr, 16);
                        }
                        else if (regValMapInfo->first == getArchSBPStr(codeInformation.mode).first || (regValMapInfo->first == getArchSBPStr(codeInformation.mode).second)){
                            STACK_ADDRESS = strtoul(regValueFirst, nullptr, 16);
                        }

                        tempRegisterValueMap[regValMapInfo->first] = regValueFirst;
                    }
                }
            }
            ImGui::PopID();

            ++regValMapInfo;
            if (regValMapInfo == registerValueMap.end()) break;

            ImGui::TableSetColumnIndex(2);
            ImGui::Text("%s", regValMapInfo->first.c_str());

            ImGui::TableSetColumnIndex(3);
            static char value2[64] = {};
            strncpy(value2, regValMapInfo->second.c_str(), sizeof(value2) - 1);
            value2[sizeof(value2) - 1] = '\0';

            ImGui::PushID(index * 2 + 1);
            ImGui::SetNextItemWidth(-FLT_MIN);
            if (ImGui::InputText(("##value2" + std::to_string(index)).c_str(), value2, IM_ARRAYSIZE(value2), ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_CharsUppercase | ImGuiInputTextFlags_CharsNoBlank | ImGuiInputTextFlags_EnterReturnsTrue)) {
                if ((strlen(value2) != 0)) {

                if (strncmp(value2, "0x", 2) != 0) {
                    registerValueMap[regValMapInfo->first] = "0x";
                    registerValueMap[regValMapInfo->first].append(value2);
                } else {
                    registerValueMap[regValMapInfo->first] = value2;
                }

                uint64_t temp;
                temp = hexStrToInt(value2);

                if (codeHasRun)
                {
                    uc_reg_write(uc, regNameToConstant(regValMapInfo->first), &temp);
                    uc_context_save(uc, context);
                }
                else{
                    if (regValMapInfo->first == getArchIPStr(codeInformation.mode)){
                        ENTRY_POINT_ADDRESS = strtoul(regValueFirst, nullptr, 10);
                    }
                    else{
                        if (regValMapInfo->first == getArchIPStr(codeInformation.mode)){
                            ENTRY_POINT_ADDRESS = strtoul(regValueFirst, nullptr, 16);
                        }
                        else if (regValMapInfo->first == getArchSBPStr(codeInformation.mode).first || (regValMapInfo->first == getArchSBPStr(codeInformation.mode).second)){
                            STACK_ADDRESS = strtoul(regValueFirst, nullptr, 16);
                        }

                        tempRegisterValueMap[regValMapInfo->first] = regValueFirst;
                    }
                }
            }
        }
            ImGui::PopID();
            ++regValMapInfo;
            if (regValMapInfo == registerValueMap.end()) break;
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