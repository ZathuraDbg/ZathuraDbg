#include "windows.hpp"
MemoryEditor stackEditor;

static void* copyBigEndian(void* _dst, void* _src, size_t s)
{
    uint8_t* dst = (uint8_t*)_dst;
    uint8_t* src = (uint8_t*)_src + s - 1;
    for (int i = 0, n = (int)s; i < n; ++i)
        memcpy(dst++, src--, 1);
    return _dst;
}


void stackWriteFunc(ImU8* data, size_t off, ImU8 d){
    LOG_DEBUG("Stack Edit request!");
    auto err = uc_mem_write(uc, STACK_ADDRESS + STACK_SIZE - off - 1, &d, 1);

    if (err){
        LOG_ERROR("Failed to write to memory. Address: " << std::hex << STACK_ADDRESS + off);
        tinyfd_messageBox("ERROR!", "Failed to write to the memory address!!", "ok", "error", 0);
    }

    char* hex = (char*)malloc(24);
    sprintf((char*)hex, "Data change: %x", d);
    LOG_DEBUG(hex);
}


void stackEditorWindow() {
    auto io = ImGui::GetIO();
    ImGui::PushFont(io.Fonts->Fonts[3]);

    static char data[5 * 1024 * 1024];
    static char temp[5 * 1024 * 1024];

    uc_mem_read(uc, STACK_ADDRESS, data, STACK_SIZE);
    copyBigEndian(temp, data, STACK_SIZE);
    memset(data, 0, STACK_SIZE);
    memcpy(data, temp, STACK_SIZE);

    // Draw the stack editor window
    stackEditor.DrawWindow("Stack", (void*)((uintptr_t)data), STACK_SIZE);
    ImGui::PopFont();
}
