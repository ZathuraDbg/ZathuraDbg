#include "windows.hpp"

tsl::ordered_map<std::string, std::string> registerValueMap = {{"RIP", "0x00"}, {"RSP", "0x00"}, {"RBP", "0x00"},{"RAX", "0x00"}, {"RBX", "0x00"}, {"RCX", "0x00"}, {"RDX", "0x00"},
                                                               {"RSI", "0x00"}, {"RDI", "0x00"}, {"R8", "0x00"}, {"R9", "0x00"}, {"R10", "0x00"}, {"R11", "0x00"}, {"R12", "0x00"},
                                                               {"R13", "0x00"}, {"R14", "0x00"}, {"R15", "0x00"}};
void updateRegs(){
    std::stringstream hex;
    std::pair<bool, uint64_t> val;
    for (auto &reg: registerValueMap) {
        val = getRegister(toLowerCase(reg.first));

        hex << "0x";
        if (val.first){
            hex << std::hex << val.second;
        }
        else {
            hex << "00";
        }

        registerValueMap[reg.first] = hex.str();
        hex.str("");
        hex.clear();
    }
}


void registerWindow() {
    updateRegs();  // Update register values
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

            // Column 0: Register Name
            ImGui::TableSetColumnIndex(0);
            float textHeight = ImGui::GetTextLineHeight();
            float frameHeight = ImGui::GetFrameHeight();
            float spacing = (frameHeight - textHeight) / 2.0f;
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + spacing);
            ImGui::Text("%s", it->first.c_str());

            // Column 1: Register Value (Editable)
            ImGui::TableSetColumnIndex(1);
            std::string value1 = it->second;

            ImGui::PushID(index * 2);
            ImGui::SetNextItemWidth(-FLT_MIN); // Use the remaining space in the column

            if (ImGui::InputText(("##value1" + std::to_string(index)).c_str(), (char*)value1.c_str(), value1.length(), (ImGuiInputTextFlags)(ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_CharsUppercase | ImGuiInputTextFlags_CharsNoBlank),
                                 nullptr, nullptr)) {
                if (strncmp(value1.c_str(), "0x", 2) != 0) {
                    registerValueMap[it->first] = "0x";
                    registerValueMap[it->first].append(value1);
                } else {
                    registerValueMap[it->first] = value1;
                }
            }
            ImGui::PopID();

            ++it;
            if (it == registerValueMap.end()) break;

            // Column 2: Next Register Name
            ImGui::TableSetColumnIndex(2);
            ImGui::Text("%s", it->first.c_str());

            // Column 3: Next Register Value (Editable)
            ImGui::TableSetColumnIndex(3);

            std::string value2 = it->second;
            if (it->first == "CS"){
                std::cout << "val 2: " << value2 << std::endl;
            }

            ImGui::PushID(index * 2 + 1);
            ImGui::SetNextItemWidth(-FLT_MIN); // Use the remaining space in the column

            if (ImGui::InputText(("##value2" + std::to_string(index)).c_str(), (char*)value2.c_str(), value2.length(), (ImGuiInputTextFlags)(ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_CharsUppercase | ImGuiInputTextFlags_CharsNoBlank),
            nullptr, nullptr)) {
                if (strncmp(value2.c_str(), "0x", 2) != 0) {
                    registerValueMap[it->first] = "0x";
                    registerValueMap[it->first].append(value2);
                } else {
                    registerValueMap[it->first] = value2;
                }
            }
            ImGui::PopID();

            ++it;
            if (it == registerValueMap.end()) break;
        }

        ImGui::EndTable();
    }

    const float footer_height_to_reserve = ImGui::GetStyle().ItemSpacing.y + ImGui::GetFrameHeightWithSpacing();

    // BeginChild with appropriate size
    // Omitting horizontal scrollbar flag and allowing ImGui to manage scrolling
    ImGui::BeginChild("ScrollingRegion", ImVec2(0, -footer_height_to_reserve), false, ImGuiWindowFlags_None);

    // You can add content here that requires scrolling

    ImGui::EndChild();

    // Command input handling
    std::list<std::string> regs;
    char input[500] = {}; // Local buffer for input command
    ImGui::PushID(&input);

    if (ImGui::InputText("Command", input, IM_ARRAYSIZE(input), ImGuiInputTextFlags_EnterReturnsTrue)) {
        regs.emplace_back(toLowerCase(input));
        std::cout << "Request to add the register: " << input << std::endl;
    }

    if (!regs.empty()) {
        for (auto& reg : regs) {
            auto regInfo = getRegister(reg);
            if (regInfo.first) {
                std::cout << "Adding the register " << reg << std::endl;
                reg = toUpperCase(reg);
                registerValueMap[reg] = regInfo.second;
            } else {
                std::cerr << "Unable to get the register: " << reg << std::endl;
            }
        }
    }

    ImGui::PopID();
    ImGui::PopFont();
}
