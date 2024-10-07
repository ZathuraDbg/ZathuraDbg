#include "codeContextMenu.hpp"
void contextMenu() {
    const auto& io = ImGui::GetIO();
    ImGui::GetStyle().Colors[ImGuiCol_PopupBg] = ImColor(0x1e, 0x20, 0x30);

    ImGui::GetStyle().Colors[ImGuiCol_HeaderHovered] = ImColor(0x18, 0x19, 0x26);
    ImGui::PushFont(io.Fonts->Fonts[RubikRegular16]);

    if (ImGui::BeginPopupContextItem("TextEditorContextMenu")) {
        if (ImGui::MenuItem("Copy", "Ctrl + C", false))
        {
            editor->Copy();
            LOG_INFO("Copied text to clipboard");
        }

        ImGui::Separator();

        if (ImGui::MenuItem("Cut", "Ctrl + X", false))
        {
            editor->Cut();
            LOG_INFO("Cut text to clipboard");
        }

        ImGui::Separator();

        if (ImGui::MenuItem("Paste", "Ctrl + V", false))
        {
            editor->Paste();
            LOG_INFO("Pasted text from clipboard");
        }

        ImGui::Separator();

        if (ImGui::MenuItem("Undo", "Ctrl + Z", false))
        {
            if (editor->CanUndo()) {
                editor->Undo();
                LOG_INFO("Performed undo!");
            }
        }

        ImGui::Separator();

        if (ImGui::MenuItem("Redo", "Ctrl + Y", false))
        {
            if (editor->CanRedo()) {
                editor->Redo();
                LOG_INFO("Performed redo!");
            }
        }

        ImGui::Separator();

        if (ImGui::MenuItem("Toggle breakpoint", "F9", false)) {
            toggleBreakpoint = true;
        }

        ImGui::Separator();

        if (!lineNumbersShown) {
            if (ImGui::MenuItem("Show line numbers", nullptr, false)) {
                editor->SetShowLineNumbersEnabled(true);
                lineNumbersShown = true;
            }
        } else {
            if (ImGui::MenuItem("Hide line numbers", nullptr,
                                false))
            {
                editor->SetShowLineNumbersEnabled(false);
                lineNumbersShown = false;
            }
        }

        ImGui::Separator();

        if (ImGui::BeginMenu("Copy as")) {
            std::stringstream selectedAsmText(editor->GetSelectedText());
            if (ImGui::MenuItem("C array")){
                if (!selectedAsmText.str().empty()) {
                    ImGui::SetClipboardText(getDataToCopy(selectedAsmText, true).c_str());
                }
            }

            if (ImGui::MenuItem("Hex")){
                std::stringstream selectedAsmStr(editor->GetSelectedText());
                if (!selectedAsmStr.str().empty()) {
                    ImGui::SetClipboardText(getDataToCopy(selectedAsmStr, false).c_str());
                }
            }
            ImGui::EndMenu();
        }

        ImGui::Separator();

        if (ImGui::MenuItem("Run until here", "F6", false)) {
            runUntilHere = true;
        }

        ImGui::Separator();
        if (!debugModeEnabled){
            if (ImGui::MenuItem("Run selected code", "F3", false)){
                runSelectedCode = true;
            }
        }

        if (ImGui::MenuItem("Go to definition", "F4")){
            goToDefinition = true;
        }

        ImGui::EndPopup();
    }

    ImGui::PopFont();
    ImGui::End();
}