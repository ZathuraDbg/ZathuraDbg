#include "windows.hpp"

static void* copyBigEndian(void* _dst, void* _src, size_t s)
{
    uint8_t* dst = (uint8_t*)_dst;
    uint8_t* src = (uint8_t*)_src + s - 1;
    for (int i = 0, n = (int)s; i < n; ++i)
        memcpy(dst++, src--, 1);
    return _dst;
}

void stackEditorWindow() {
    auto io = ImGui::GetIO();
    static MemoryEditor stackEditor;
    stackEditor.OptShowAscii = false;
    stackEditor.Cols = 8;

    ImGui::PushFont(io.Fonts->Fonts[3]);
    static char data[5 * 1024 * 1024];

    // Read data from the stack
    uc_mem_read(uc, STACK_ADDRESS, data, STACK_SIZE);

    // Create a temporary buffer to hold the big-endian copy
    static char temp[5 * 1024 * 1024];

    // Copy data to the temporary buffer in big-endian format
    copyBigEndian(temp, data, STACK_SIZE);

    // Zero out the original data after copying
    memset(data, 0, STACK_SIZE);

    // Copy the temporary buffer back to the original data buffer
    memcpy(data, temp, STACK_SIZE);

    // Draw the stack editor window
    stackEditor.DrawWindow("Stack", (void*)((uintptr_t)data + 0x4), STACK_SIZE);
    ImGui::PopFont();
}
