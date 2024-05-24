#include "windows.hpp"

void stackEditorWindow(){
    auto io = ImGui::GetIO();
    static MemoryEditor mem_edit_2;
    mem_edit_2.OptShowAscii = false;
    mem_edit_2.Cols = 8;

    ImGui::PushFont(io.Fonts->Fonts[3]);
//  replace with stack stuff
    static char data[5 * 1024 * 1024];
    size_t data_size = 0x10000;

    uc_mem_read(uc, STACK_ADDRESS, data, data_size);
    mem_edit_2.DrawWindow("Stack", (void*)data, STACK_SIZE);
    ImGui::PopFont();
}
