#include "windows.hpp"
MemoryEditor memoryEditorWindow;

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

void hexEditorWindow(){
    auto io = ImGui::GetIO();
    ImGui::PushFont(io.Fonts->Fonts[3]);
    static char data[0x3000];
    memset(data, 0, 0x3000);

    uc_mem_read(uc, ENTRY_POINT_ADDRESS, data, 0x3000);
    memoryEditorWindow.DrawWindow("Memory Editor", (void*)data, 0x3000);
    ImGui::PopFont();
}
