#include "windows.hpp"
#include "../app.hpp"

MemoryEditor memoryEditorWindow;
std::vector<newMemEditWindowsInfo> newMemEditWindows{};

void hexWriteFunc(ImU8* data, size_t off, ImU8 d){
    auto err = uc_mem_write(uc, MEMORY_EDITOR_BASE + off, &d, 1);

    if (err){
        LOG_ERROR("Failed to write to memory. Address: " << MEMORY_EDITOR_BASE + off);
        char* hex = (char*)malloc(24);
        sprintf((char*)hex, "Data change: %x", d);
        LOG_ERROR(hex);
        tinyfd_messageBox("ERROR!", "Failed to write to the memory address!!", "ok", "error", 0);
    }
}

std::pair<size_t, size_t> infoPopup(const std::string& title = "", const std::string& sizeHint = "") {
    ImGui::OpenPopup("InputPopup");
    std::pair<size_t, size_t> windowInfo;

    ImVec2 parentPos = ImGui::GetWindowPos();
    ImVec2 parentSize = ImGui::GetWindowSize();
    ImVec2 windowSize = ImGui::GetWindowSize();

    ImVec2 popupSize = ImVec2(290, 160);
    ImVec2 popupPos = parentPos + ImVec2((parentSize.x - popupSize.x) * 0.5f, (parentSize.y - popupSize.y) * 0.5f);

    const char *text = title.c_str();
    auto windowTextPos = ImGui::CalcTextSize(text);

    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[SatoshiBold18]);
    ImGui::PushStyleVar(ImGuiStyleVar_PopupBorderSize, 5.0f);
    ImGui::SetNextWindowPos(popupPos, ImGuiCond_Appearing);
    static char addrNewWin[120] = "";
    static char size[30] = "";
    bool enterReceived = false;

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
        ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[JetBrainsMono20]);

        ImGui::PushItemWidth(180);
        if (ImGui::InputTextWithHint("##text", "0x....", addrNewWin, IM_ARRAYSIZE(addrNewWin), ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CallbackCharFilter, checkHexCharsCallback, nullptr)){
            windowInfo.first = hexStrToInt(addrNewWin);
        }

        ImGui::PopFont();
        ImGui::PopItemWidth();
        ImGui::Dummy(ImVec2(22.0f, 0.0f));
        ImGui::SameLine(0, 14);
        ImGui::Text("Size: ");
        ImGui::SameLine(0, 5);

        ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[JetBrainsMono20]);
        ImGui::PushItemWidth(180);
        ImGui::InputTextWithHint("##size", sizeHint.empty() ? "in bytes" : sizeHint.c_str(),  size, IM_ARRAYSIZE(size), ImGuiInputTextFlags_CharsDecimal, nullptr, nullptr);

        if (ImGui::IsKeyPressed(ImGuiKey_Enter)){
            enterReceived = true;
        }

        ImGui::PopFont();
        ImGui::PopItemWidth();
        ImGui::Dummy(ImVec2(0, 12.0f));

        windowSize = ImGui::GetWindowSize();
        ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[SatoshiBold18]);

        ImGui::SetCursorPosX(windowSize.y + 10);
        if (ImGui::Button("OK") || (enterReceived))
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

MemoryEditor::fillRangeInfoT popupTwo() {
    ImGui::OpenPopup("InputPopup");
    MemoryEditor::fillRangeInfoT fillRangeInfo{};
//    std::pair<size_t, size_t> fillRangeInfo;
    ImVec2 parentPos = ImGui::GetWindowPos();
    ImVec2 parentSize = ImGui::GetWindowSize();
    ImVec2 windowSize = ImGui::GetWindowSize();

    ImVec2 popupSize = ImVec2(290, 160);
    ImVec2 popupPos = parentPos + ImVec2((parentSize.x - popupSize.x) * 0.5f, (parentSize.y - popupSize.y) * 0.5f);

    const char *text = "Fill memory with byte";
    auto windowTextPos = ImGui::CalcTextSize(text);

    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[SatoshiBold18]);
    ImGui::PushStyleVar(ImGuiStyleVar_PopupBorderSize, 5.0f);
    ImGui::SetNextWindowPos(popupPos, ImGuiCond_Appearing);
    static char addrNewWin[120] = "";
    static char size[30] = "";
    static char byteHex[40] = "";
    bool enterReceived = false;

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
        ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[JetBrainsMono20]);

        ImGui::PushItemWidth(180);
        if (ImGui::InputTextWithHint("##text", "0x....", addrNewWin, IM_ARRAYSIZE(addrNewWin), ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CallbackCharFilter, checkHexCharsCallback, nullptr)){
            fillRangeInfo.address = hexStrToInt(addrNewWin);
        }

        ImGui::PopFont();
        ImGui::PopItemWidth();
        ImGui::Dummy(ImVec2(22.0f, 0.0f));
        ImGui::SameLine(0, 14);
        ImGui::Text("Size: ");
        ImGui::SameLine(0, 5);

        ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[JetBrainsMono20]);
        ImGui::PushItemWidth(180);
        ImGui::InputTextWithHint("##size", "Size to fill",  size, IM_ARRAYSIZE(size), ImGuiInputTextFlags_CharsDecimal, nullptr, nullptr);
        ImGui::PopFont();
        ImGui::PopItemWidth();
        ImGui::Dummy(ImVec2(22.0f, 0.0f));
        ImGui::SameLine(0, 12);
        ImGui::Text("Byte: ");
        ImGui::SameLine(0, 5);
        ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[JetBrainsMono20]);
        ImGui::PushItemWidth(180);
        ImGui::InputTextWithHint("##byteHex", "As Hex", byteHex, IM_ARRAYSIZE(byteHex), ImGuiInputTextFlags_CharsNoBlank | ImGuiInputTextFlags_CallbackAlways, checkHexCharsCallback, nullptr);

        if (ImGui::IsKeyPressed(ImGuiKey_Enter)){
            enterReceived = true;
        }

        ImGui::PopFont();
        ImGui::PopItemWidth();
        ImGui::Dummy(ImVec2(0, 12.0f));

        windowSize = ImGui::GetWindowSize();
        ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[SatoshiBold18]);

        ImGui::SetCursorPosX(windowSize.y + 10);
        if (ImGui::Button("OK") || (enterReceived))
        {
            ImGui::PopFont();
            ImGui::PopFont();
            ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
            ImGui::PopStyleVar();
            fillRangeInfo.address = hexStrToInt(addrNewWin);
            fillRangeInfo.size = atol(size);
            fillRangeInfo.character = (char)strtol(byteHex, nullptr, 16);

            if (!fillRangeInfo.address && (!fillRangeInfo.size) && (!fillRangeInfo.character)){
                return {0, 0, 0};
            }

            return fillRangeInfo;
        }

        ImGui::SameLine(0, 3);

        if (ImGui::Button("CANCEL"))
        {
            ImGui::PopFont();
            ImGui::PopFont();
            ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
            ImGui::PopStyleVar();
            return {0, 1, -1};
        }

        ImGui::PopFont();
        ImGui::EndPopup();
    }
    ImGui::PopStyleVar();
    ImGui::PopFont();

    return fillRangeInfo;
}

bool createNewWindow(){
    auto [address, size] = infoPopup("New Memory Editor Window");
    if (address && size){
        MemoryEditor memEdit;

        memoryEditorWindow.HighlightColor = ImColor(59, 60, 79);

       /*
        * When the OptShowAddWindowButton is set and the user clicks on the "+" icon
        * it causes an unidentified bug which leads to the program getting stuck
        * if the newly created memory editor window is not docked.
        * The easy fix for this is to find a way to dock the newly created windows automatically
        * as tabs next to the previous memory editor window.
       */

        memoryEditorWindow.OptShowAddWindowButton = false;
//        memoryEditorWindow.NewWindowInfoFn = createNewWindow;
        newMemEditWindowsInfo memWindowInfo = {memoryEditorWindow, address, size};
        newMemEditWindows.push_back(memWindowInfo);

        return true;
    }
    else if (address && (!size) || (!address && size)){
        return true;
    }

    return false;
}

bool setBaseAddr(){
    auto [address, size] = infoPopup("Modify Base Address", "8192 bytes default");
    if (address && size){
        MEMORY_EDITOR_BASE = address;
        return true;
    }
    else if (address && (!size) || (!address && size)){
        return true;
    }

    return false;
}


bool fillMemoryRange(){
    auto [address, size, character] = popupTwo();
    if (address && size && character){
//        fillMemoryRange(address, size, character);
        return true;
    }
    else if (address && (!size) || (!address && size)){
        return true;
    }

    return false;
}

void hexEditorWindow(){
    auto io = ImGui::GetIO();
    char data[0x3000];
    ImGui::PushFont(io.Fonts->Fonts[3]);
    memset(data, 0, 0x3000);

    uc_mem_read(uc, MEMORY_EDITOR_BASE, data, 0x3000);
    memoryEditorWindow.HighlightColor = ImColor(59, 60, 79);
    memoryEditorWindow.OptShowAddWindowButton = true;
    memoryEditorWindow.NewWindowInfoFn = createNewWindow;
    memoryEditorWindow.ShowRequiredButton = stackEditor.ShowRequiredButton = &showRequiredButton;
    memoryEditorWindow.OptShowSetBaseAddrOption = true;
    memoryEditorWindow.OptFillMemoryRange = true;
    memoryEditorWindow.SetBaseAddress = setBaseAddr;
    memoryEditorWindow.FillMemoryRange = popupTwo;
    memoryEditorWindow.DrawWindow("Memory Editor", (void*)data, 0x3000, MEMORY_EDITOR_BASE);
    int i = 0;

    if (!newMemEditWindows.empty()){
        for (auto& info: newMemEditWindows){
            char newMemData[info.size];
            memset(newMemData, 0, info.size);

            uc_err err = uc_mem_read(uc, info.address, newMemData, info.size);
            if (err){
            }

            info.memEditor.DrawWindow(("Memory Editor " + std::to_string(++i)).c_str(), (void*)newMemData, info.size, info.address);
        }
    }
    ImGui::PopFont();
}
