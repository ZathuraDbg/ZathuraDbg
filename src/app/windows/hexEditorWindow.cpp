#include "windows.hpp"
#include "../app.hpp"

MemoryEditor memoryEditorWindow;
std::vector<newMemEditWindowsInfo> newMemEditWindows{};

void hexWriteFunc(ImU8* data, size_t off, ImU8 d){
    auto err = uc_mem_write(uc, MEMORY_EDITOR_BASE + off, &d, 1);

    if (err){
        LOG_ERROR("Failed to write to memory. Address: " << MEMORY_EDITOR_BASE + off);
        const auto hex = static_cast<char *>(malloc(24));
        sprintf(static_cast<char *>(hex), "Data change: %x", d);
        LOG_ERROR(hex);
        tinyfd_messageBox("ERROR!", "Failed to write to the memory address!!", "ok", "error", 0);
    }
}

std::pair<size_t, size_t> infoPopup(const std::string& title, const std::string& sizeHint) {
    ImGui::OpenPopup("InputPopup");
    std::pair<size_t, size_t> windowInfo{};

    const ImVec2 parentPos = ImGui::GetWindowPos();
    const ImVec2 parentSize = ImGui::GetWindowSize();
    ImVec2 windowSize = ImGui::GetWindowSize();

    constexpr auto popupSize = ImVec2(290, 160);
    const ImVec2 popupPos = parentPos + ImVec2((parentSize.x - popupSize.x) * 0.5f, (parentSize.y - popupSize.y) * 0.5f);

    const char *text = title.c_str();
    const auto windowTextPos = ImGui::CalcTextSize(text);

    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[SatoshiBold18]);
    ImGui::PushStyleVar(ImGuiStyleVar_PopupBorderSize, 5.0f);
    ImGui::SetNextWindowPos(popupPos, ImGuiCond_Appearing);
    static char addrNewWin[120] = "";
    static char size[30] = "";

    if (ImGui::BeginPopup("InputPopup", ImGuiWindowFlags_AlwaysAutoResize)) {
        bool enterReceived = false;
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

            addrNewWin[0] = '\0';
            size[0] = '\0';
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
            addrNewWin[0] = '\0';
            size[0] = '\0';
            return {0, 1};
        }

        ImGui::PopFont();
        ImGui::EndPopup();
    }
    ImGui::PopStyleVar();
    ImGui::PopFont();

    return windowInfo;
}

MemoryEditor::fillRangeInfoT fillMemoryWithBytePopup() {
    ImGui::OpenPopup("FillBytePopup");
    MemoryEditor::fillRangeInfoT fillRangeInfo{};
//    std::pair<size_t, size_t> fillRangeInfo;
    ImVec2 parentPos = ImGui::GetWindowPos();
    ImVec2 parentSize = ImGui::GetWindowSize();
    ImVec2 windowSize = ImGui::GetWindowSize();

    ImVec2 popupSize = ImVec2(290, 160);
    ImVec2 popupPos = parentPos + ImVec2((parentSize.x - popupSize.x) * 0.5f, (parentSize.y - popupSize.y) * 0.5f);

    const auto text = "Fill memory with byte";
    const auto windowTextPos = ImGui::CalcTextSize(text);

    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[SatoshiBold18]);
    ImGui::PushStyleVar(ImGuiStyleVar_PopupBorderSize, 5.0f);
    ImGui::SetNextWindowPos(popupPos, ImGuiCond_Appearing);
    static char addrNewWin[120] = "";
    static char size[30] = "";
    static char byteHex[40] = "";

    if (ImGui::BeginPopup("FillBytePopup", ImGuiWindowFlags_AlwaysAutoResize)) {
        bool enterReceived = false;
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
        ImGui::InputTextWithHint("##byteHex", "As Hex", byteHex, IM_ARRAYSIZE(byteHex),ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CallbackCharFilter, checkHexCharsCallback, nullptr);

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

void MemoryEditor::GoToPopup(){
    char inputText[200] = "";
    static bool setFocus = true;
    auto io = ImGui::GetIO();
    ImGui::PushFont(io.Fonts->Fonts[SatoshiBold18]);

    ImGui::OpenPopup("Gotopopup");
    auto text = "Go to address";

    ImVec2 windowPos = ImGui::GetWindowPos();
    ImVec2 windowTextPos= ImGui::CalcTextSize(text);
    ImVec2 windowSize = ImGui::GetWindowSize();

    ImVec2 popupSize = ImVec2(300, 100); // Adjust based on your popup size
    ImVec2 popupPos = windowPos + ImVec2((windowSize.x - popupSize.x) * 0.5f, (windowSize.y - popupSize.y) * 0.5f);

    ImGui::SetNextWindowPos(popupPos, ImGuiCond_Appearing);

    ImGui::GetStyle().Colors[ImGuiCol_PopupBg] = ImColor(0x1e, 0x20, 0x30);
    ImGui::GetStyle().PopupBorderSize = 5.0f;

    uint64_t hexInt = -1;
    ImGui::SetNextWindowSize(popupSize, ImGuiCond_Appearing);
    if (ImGui::BeginPopup("Gotopopup", ImGuiWindowFlags_AlwaysAutoResize))
    {
        windowSize = ImGui::GetWindowSize();

        ImGui::SetCursorPosX((windowSize.x - windowTextPos.x) * 0.5f);
        ImGui::Text("%s", text);

        ImGui::Dummy(ImVec2(0.0f, 15.0f));
        ImGui::NewLine();
        ImGui::SameLine(0, 10);

        ImGui::Text("Address: ");

        ImGui::SameLine(0, 5);
        ImGui::PushItemWidth(150);

        bool entered;
        auto flags = ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CallbackCharFilter;
        entered = ImGui::InputTextWithHint("##input", "0x...", inputText, IM_ARRAYSIZE(inputText), flags,
                                           checkHexCharsCallback);

        if (setFocus){
            ImGui::SetKeyboardFocusHere(-1);
            setFocus = false;
        }

        if (entered){
            hexInt = hexStrToInt(inputText);
            KeepGoToPopup = false;
            setFocus = true;
        }

        ImGui::PopItemWidth();
        ImGui::Dummy(ImVec2(0, 8.0f));
        ImGui::SetCursorPosX(windowSize.y + windowSize.y - 100);

        if (ImGui::Button("OK") || (hexInt != -1))
        {
            if (hexInt == -1){
                hexInt = hexStrToInt(inputText);
            }

            GotoAddr = hexInt - BaseDisplayAddr;
            setFocus = true;
            KeepGoToPopup = false;
            ImGui::CloseCurrentPopup();
        }

        ImGui::SameLine(0, 3);

        if (ImGui::Button("CANCEL"))
        {

            KeepGoToPopup = false;
            setFocus = true;
            ImGui::CloseCurrentPopup();
        }

        ImGui::EndPopup();
    }

        ImGui::PopFont();
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

std::variant<bool, std::pair<void*, size_t>> setBaseAddr2(uintptr_t baseAddr, uintptr_t editorSize){
    if (baseAddr && editorSize) {
        MEMORY_EDITOR_BASE = baseAddr;
        MEMORY_DEFAULT_SIZE = editorSize;
        std::pair<void*, size_t> ret = {(void*)baseAddr, editorSize};
        return ret;
    }

    auto [address, size] = infoPopup("Modify Base Address", "8192 bytes default");
    if (address && size){
        MEMORY_EDITOR_BASE = address;
        std::pair<void*, size_t> ret = {(void*)address, size};
        return ret;
    }
    else if (address && (!size)) {
        MEMORY_EDITOR_BASE = address;
        MEMORY_DEFAULT_SIZE = 8192;
        std::pair<void*, size_t> ret = {(void*)address, 8192};
        return ret;
    }
    else if ((!address && size)){
        return true;
    }

    return false;
}


bool fillMemoryRange(){
    auto [address, size, character] = fillMemoryWithBytePopup();
    if (address && size && character){
        return true;
    }
    else if (address && (!size) || (!address && size)){
        return true;
    }

    return false;
}


void hexEditorWindow(){
    const auto io = ImGui::GetIO();
    char data[0x3000];
    ImGui::PushFont(io.Fonts->Fonts[3]);
    memset(data, 0, 0x3000);

    if (!uc) {
        ImGui::PopFont();
        return;
    }

    uc_mem_read(uc, MEMORY_EDITOR_BASE, data, 0x3000);
    memoryEditorWindow.HighlightColor = ImColor(59, 60, 79);
    memoryEditorWindow.OptShowAddWindowButton = true;
    memoryEditorWindow.NewWindowInfoFn = createNewWindow;
    memoryEditorWindow.ShowRequiredButton = stackEditor.ShowRequiredButton = &showRequiredButton;
    memoryEditorWindow.OptShowSetBaseAddrOption = true;
    memoryEditorWindow.OptFillMemoryRange = true;
    memoryEditorWindow.SetBaseAddress2 = setBaseAddr2;
    memoryEditorWindow.FillMemoryRange = fillMemoryWithBytePopup;
    memoryEditorWindow.DrawWindow("Memory Editor", (void*)data, 0x3000, MEMORY_EDITOR_BASE);

    if (!newMemEditWindows.empty()) {
        int i = 0;
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
