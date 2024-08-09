#include "windows.hpp"
MemoryEditor stackEditor;

static void* copyBigEndian(void* _dst, const void* _src, size_t s)
{
    uint8_t* dst = (uint8_t*)_dst;
    const uint8_t* src = (const uint8_t*)_src + s - 1;
    for (size_t i = 0; i < s; ++i)
    {
        dst[i] = *src--;
    }
    return _dst;
}

void stackWriteFunc(ImU8* data, size_t off, ImU8 d) {
    LOG_DEBUG("Stack Edit request!");
    auto err = uc_mem_write(uc, STACK_ADDRESS + STACK_SIZE - off - 1, &d, 1);

    if (err) {
        LOG_ERROR("Failed to write to memory. Address: " << std::hex << STACK_ADDRESS + off);
        tinyfd_messageBox("ERROR!", "Failed to write to the memory address!!", "ok", "error", 0);
    }

    char hex[24];
    snprintf(hex, sizeof(hex), "Data change: %x", d);
    LOG_DEBUG(hex);
}
uint64_t stackErrorAddr = 0;

bool showPopupError = false;
void popup(){
    auto text = "Stack in unmapped memory region!";

    ImVec2 windowPos = ImGui::GetWindowPos();
    ImVec2 windowTextPos= ImGui::CalcTextSize(text);
    ImVec2 windowSize = ImGui::GetWindowSize();
    ImVec2 popupSize = ImVec2(350, 110);
    ImVec2 popupPos = windowPos + ImVec2((windowSize.x - popupSize.x) * 0.5f, (windowSize.y - popupSize.y) * 0.5f);

    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[SatoshiBold24]);
    ImGui::SetNextWindowPos(popupPos, ImGuiCond_Appearing);

    ImGui::GetStyle().Colors[ImGuiCol_PopupBg] = ImColor(0x1e, 0x20, 0x30);
    ImGui::GetStyle().PopupBorderSize = 5.0f;
    ImGui::SetNextWindowSize(popupSize, 0);
    if (ImGui::BeginPopup("InputPopup", ImGuiWindowFlags_AlwaysAutoResize))
    {
        windowSize = ImGui::GetWindowSize();

        ImGui::SetCursorPosX((windowSize.x - windowTextPos.x) * 0.5f);
        ImGui::Text("%s", text);
        ImGui::SeparatorEx(ImGuiSeparatorFlags_Horizontal, 6.0f);
        ImGui::Dummy(ImVec2(0.0f, 5.0f));
        ImGui::SameLine(0, 15);
        ImGui::Text("Do you want to map the stack?");
//        ImGui::SameLine(0, 5);
        ImGui::Dummy(ImVec2(0, 4.0f));
        ImGui::SetCursorPosX(ImGui::CalcTextSize(text).x - 40);
        if (ImGui::Button("Allocate"))
        {
            uc_mem_map(uc, STACK_ADDRESS, STACK_SIZE, UC_PROT_ALL);
            showPopupError = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine(0, 3);
        if (ImGui::Button("Cancel"))
        {
            showPopupError = false;
            ImGui::CloseCurrentPopup();
        }

        ImGui::EndPopup();
    }
    ImGui::PopFont();
}

void stackEditorWindow() {
    auto io = ImGui::GetIO();
    ImGui::PushFont(io.Fonts->Fonts[3]);

    static char data[5 * 1024 * 1024];
    static char temp[5 * 1024 * 1024];

    memset(data, 0, sizeof(data));
    memset(temp, 0, sizeof(temp));

    auto err = uc_mem_read(uc, STACK_ADDRESS, temp, STACK_SIZE);
    if ((err == UC_ERR_READ_UNMAPPED) && (stackErrorAddr != STACK_ADDRESS && (STACK_ADDRESS != 0))) {
        LOG_ERROR("Failed to read memory. Address: " << std::hex << STACK_ADDRESS);
        stackErrorAddr = STACK_ADDRESS;
//        tinyfd_messageBox("ERROR!", "Failed to read memory!!", "ok", "error", 0);
        showPopupError = true;
        ImGui::PopFont();
        return;
    }

    if (showPopupError){
//        ImGui::OpenPopup("Stack in unmapped region!");
        ImGui::OpenPopup("InputPopup");
        popup();
//        showError("Do you want to map the memory to continue?");
    }

    copyBigEndian(data, temp, STACK_SIZE);

    stackEditor.DrawWindow("Stack", (void*)((uintptr_t)data), STACK_SIZE);
    ImGui::PopFont();
}
