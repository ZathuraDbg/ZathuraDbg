#include "windows.hpp"

static void* copyBigEndian(void* _dst, void* _src, size_t s)
{
    uint8_t* dst = (uint8_t*)_dst;
    uint8_t* src = (uint8_t*)_src + s - 1;
    for (int i = 0, n = (int)s; i < n; ++i)
        memcpy(dst++, src--, 1);
    return _dst;
}

void stackEditorWindow(){
    auto io = ImGui::GetIO();
    static MemoryEditor stackEditor;
    stackEditor.OptShowAscii = false;
    stackEditor.Cols = 8;

    ImGui::PushFont(io.Fonts->Fonts[3]);
    static char data[5 * 1024 * 1024];

    //  pop does not remove the popped element from the stack, it only copies it
    uc_mem_read(uc, STACK_ADDRESS, data, STACK_SIZE);
    copyBigEndian(data, data, STACK_SIZE );
    memset((void*)((uintptr_t)data + STACK_SIZE / 2), 0, STACK_SIZE / 2);
    stackEditor.DrawWindow("Stack", (void*)((uintptr_t)data + 0x4), STACK_SIZE);
    ImGui::PopFont();
}