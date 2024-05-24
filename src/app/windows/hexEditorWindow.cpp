#include "windows.hpp"

void hexEditorWindow(){
    LOG_DEBUG("Hex Editor Window");
    auto io = ImGui::GetIO();
    static MemoryEditor mem_edit_2;
    ImGui::PushFont(io.Fonts->Fonts[3]);
    static char data[0x3000];

    uc_mem_read(uc, ENTRY_POINT_ADDRESS, data, 0x3000);
    mem_edit_2.DrawWindow("Memory Editor", (void*)data, 0x3000);
    ImGui::PopFont();
    LOG_DEBUG("Hex Editor Window Done");
}
