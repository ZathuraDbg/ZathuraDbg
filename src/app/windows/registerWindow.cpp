#include "windows.hpp"
bool codeHasRun = false;
tsl::ordered_map<std::string, std::string> registerValueMap = {{"RIP", "0x00"}, {"RSP", "0x00"}, {"RBP", "0x00"},{"RAX", "0x00"}, {"RBX", "0x00"}, {"RCX", "0x00"}, {"RDX", "0x00"},
                                                               {"RSI", "0x00"}, {"RDI", "0x00"}, {"R8", "0x00"}, {"R9", "0x00"}, {"R10", "0x00"}, {"R11", "0x00"}, {"R12", "0x00"},
                                                               {"R13", "0x00"}, {"R14", "0x00"}, {"R15", "0x00"}, {"CS", "0x00"}, {"DS", "0x00"}, {"ES", "0x00"}, {"FS", "0x00"}, {"GS", "0x00"}, {"SS", "0x00"}};

void updateRegs(){
    std::stringstream hex;
    std::pair<bool, uint64_t> val;
    for (auto &reg: registerValueMap) {
        val = getRegister(toLowerCase(reg.first));

        hex << "0x";
        if (val.first){
            if (val.second == 0){
                hex << std::hex << "00";
            }
            else{
                hex << std::hex << val.second;
            }
        }
        else {
            hex << "00";
        }

        registerValueMap[reg.first] = hex.str();
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

void registerWindow() {
    updateRegs();
    auto io = ImGui::GetIO();
    ImGui::PushFont(io.Fonts->Fonts[3]);  // Use the appropriate font index

    // Begin the table to display registers and their values
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
            ImGui::SetNextItemWidth(-FLT_MIN); // Use the remaining space in the column
            if (ImGui::InputText(("##value1" + std::to_string(index)).c_str(), value1, IM_ARRAYSIZE(value1), ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_CharsUppercase | ImGuiInputTextFlags_CharsNoBlank)) {
                if (strncmp(value1, "0x", 2) != 0) {
                    registerValueMap[it->first] = "0x";
                    registerValueMap[it->first].append(value1);
                    int val1 = std::stoi(value1, nullptr, 16);
                    LOG_DEBUG("Register: " << it->first << "; Value: " << value1 << "; after stoi" << val1);
                    uc_reg_write(uc, regNameToConstant(it->first), &val1);
                } else {
                    int val1 = std::stoi(value1, nullptr, 16);
                    LOG_DEBUG("Register else: " << it->first << "; Value: " << value1 << "; after stoi" << val1);
                    uc_reg_write(uc, regNameToConstant(it->first), &val1);
                    registerValueMap[it->first] = value1;
                }

                uc_context_save(uc, context);
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
            ImGui::SetNextItemWidth(-FLT_MIN); // Use the remaining space in the column
            if (ImGui::InputText(("##value2" + std::to_string(index)).c_str(), value2, IM_ARRAYSIZE(value2), ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_CharsUppercase | ImGuiInputTextFlags_CharsNoBlank)) {
                if (strncmp(value2, "0x", 2) != 0) {
                    registerValueMap[it->first] = "0x";
                    registerValueMap[it->first].append(value2);
                    int val1 = std::stoi(value2, nullptr, 16);
                    LOG_DEBUG("Register: " << it->first << "; Value: " << value2<< "; after stoi" << val1);
                    uc_reg_write(uc, regNameToConstant(it->first), &val1);
                } else {
                    registerValueMap[it->first] = value2;
                    int val1 = std::stoi(value2, nullptr, 16);
                    LOG_DEBUG("Register: " << it->first << "; Value: " << value2 << "; after stoi" << val1);
                    uc_reg_write(uc, regNameToConstant(it->first), &val1);
                }

                uc_context_save(uc, context);
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
    char input[500] = {}; // Local buffer for input command

    ImGui::PushID(&input);
    ImGui::Text("Add registers: ");
    ImGui::SameLine();

    if (ImGui::InputText("##registerInput", input, IM_ARRAYSIZE(input), ImGuiInputTextFlags_EnterReturnsTrue)) {
        registerString += toLowerCase(input);
        LOG_DEBUG("Request to add the register: " << input);
    }

    std::vector<std::string> regsVec = {};
    if (!registerString.empty()) {
        auto regs = parseRegisters(registerString);
        for (auto& reg : regs) {
            auto regInfo = getRegister(reg);
            if (regInfo.first) {
                regsVec = parseRegisters(reg);
                LOG_DEBUG("Adding the register " << reg);
                reg = toUpperCase(reg);
                registerValueMap[reg] = regInfo.second;
            } else {
                LOG_ERROR("Unable to get the register: " << reg);
            }
        }
    }

    ImGui::PopID();
    ImGui::PopFont();
}