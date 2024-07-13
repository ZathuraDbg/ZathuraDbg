#include "windows.hpp"

MemoryEditor memoryEditorWindow;
std::vector<newMemEditWindowsInfo> newMemEditWindows{};

void hexWriteFunc(ImU8* data, size_t off, ImU8 d){
    auto err = uc_mem_write(uc, ENTRY_POINT_ADDRESS + off, &d, 1);

    if (err){
        LOG_ERROR("Failed to write to memory. Address: " << ENTRY_POINT_ADDRESS + off);
        char* hex = (char*)malloc(24);
        sprintf((char*)hex, "Data change: %x", d);
        LOG_ERROR(hex);
        tinyfd_messageBox("ERROR!", "Failed to write to the memory address!!", "ok", "error", 0);
    }
}

int checkCB(ImGuiInputTextCallbackData* data) {
    std::cout << data->BufTextLen << std::endl;
    if (data->BufTextLen){
        std::string input(data->Buf, data->BufTextLen);
        std::cout << input << std::endl;
    }
    return 0;
}

std::pair<size_t, size_t> newWindowInfoFunc() {
    ImGui::OpenPopup("InputPopup");
    std::pair<size_t, size_t> windowInfo;

    ImVec2 parentPos = ImGui::GetWindowPos();
    ImVec2 parentSize = ImGui::GetWindowSize();
    ImVec2 windowSize = ImGui::GetWindowSize();

    ImVec2 popupSize = ImVec2(290, 160);
    ImVec2 popupPos = parentPos + ImVec2((parentSize.x - popupSize.x) * 0.5f, (parentSize.y - popupSize.y) * 0.5f);

    const char *text = "New Memory Editor Window";
    auto windowTextPos = ImGui::CalcTextSize(text);

    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[SatoshiBold18]);
    ImGui::PushStyleVar(ImGuiStyleVar_PopupBorderSize, 5.0f);
    ImGui::SetNextWindowPos(popupPos, ImGuiCond_Appearing);
    static char addrNewWin[120] = "";
    static char size[30] = "";
    bool enterRecieved = false;

    if (ImGui::BeginPopup("InputPopup", ImGuiWindowFlags_AlwaysAutoResize)) {
        windowSize = ImGui::GetWindowSize();
        ImGui::SetCursorPosX((windowSize.x - windowTextPos.x) * 0.5f);
        ImGui::Text("%s", text);
        ImGui::SeparatorEx(ImGuiSeparatorFlags_Horizontal, 3);
        ImGui::Dummy(ImVec2(0.0f, 10.0f));
        ImGui::NewLine();
        ImGui::SameLine(0, 10);

        ImGui::Text("Address: ");
        ImGui::SameLine(0, 5);

        ImGui::PushItemWidth(180);
        if (ImGui::InputTextWithHint("##text", "0x....", addrNewWin, IM_ARRAYSIZE(addrNewWin), ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CallbackAlways, checkHexCharsCallback, nullptr)){
            windowInfo.first = hexStrToInt(addrNewWin);
        }

        ImGui::PopItemWidth();
        ImGui::Dummy(ImVec2(22.0f, 0.0f));
        ImGui::SameLine(0, 14);
        ImGui::Text("Size: ");
        ImGui::SameLine(0, 5);


        ImGui::PushItemWidth(180);
        if (ImGui::InputTextWithHint("##size", "in bytes", size, IM_ARRAYSIZE(size), ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CharsDecimal, nullptr, nullptr)){
            windowInfo.second = atol(size);
            enterRecieved = true;
        }

        ImGui::PopItemWidth();
        ImGui::Dummy(ImVec2(0, 12.0f));

        windowSize = ImGui::GetWindowSize();
        ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[SatoshiBold18]);

        ImGui::SetCursorPosX(windowSize.y + 10);
        if (ImGui::Button("OK") || (enterRecieved))
        {
            ImGui::PopFont();
            ImGui::PopFont();
            ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
            ImGui::PopStyleVar();
            windowInfo.first = hexStrToInt(addrNewWin);
            windowInfo.second = atol(size);

            if (!windowInfo.first && (!windowInfo.second)){
                return {0, 1};
            }

            return windowInfo;
        }

        ImGui::SameLine(0, 3);

        if (ImGui::Button("CANCEL"))
        {
            ImGui::PopFont();
            ImGui::PopFont();
            ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
            ImGui::PopStyleVar();
            return {0, 1};
        }

        ImGui::PopFont();
        ImGui::EndPopup();
    }
    ImGui::PopStyleVar();
    ImGui::PopFont();

    return windowInfo;
}

bool createNewWindow(){
    auto [address, size] = newWindowInfoFunc();
    if (address && size){
        MemoryEditor memEdit;

        memoryEditorWindow.HighlightColor = ImColor(59, 60, 79);
        memoryEditorWindow.OptShowAddWindowButton = true;
        memoryEditorWindow.newWindowFn = createNewWindow;
        newMemEditWindowsInfo memWindowInfo = {memoryEditorWindow, address, size};
        newMemEditWindows.push_back(memWindowInfo);

        return true;
    }
    else if (address && (!size) || (!address && size)){
        return true;
    }

    return false;
}

void hexEditorWindow(){
    auto io = ImGui::GetIO();
    ImGui::PushFont(io.Fonts->Fonts[3]);
    static char data[0x3000];
    memset(data, 0, 0x3000);

    uc_mem_read(uc, ENTRY_POINT_ADDRESS, data, 0x3000);
    memoryEditorWindow.HighlightColor = ImColor(59, 60, 79);
    memoryEditorWindow.OptShowAddWindowButton = true;
    memoryEditorWindow.newWindowFn = createNewWindow;
    memoryEditorWindow.DrawWindow("Memory Editor", (void*)data, 0x3000);
    int i = 0;

    if (!newMemEditWindows.empty()){
        for (auto& info: newMemEditWindows){
            char newMemData[info.size];
            memset(newMemData, 0, info.size);

            uc_err err = uc_mem_read(uc, info.address, newMemData, info.size);
            if (err){
//                std::cout << "Unable to read from the address" << std::endl;
            }

            info.memEditor.DrawWindow(("Memory Editor " + std::to_string(++i)).c_str(), (void*)newMemData, info.size);
        }
    }
    ImGui::PopFont();
}
