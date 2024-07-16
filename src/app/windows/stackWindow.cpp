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

void stackEditorWindow() {
    auto io = ImGui::GetIO();
    ImGui::PushFont(io.Fonts->Fonts[3]);

    static char data[5 * 1024 * 1024];
    static char temp[5 * 1024 * 1024];

    memset(data, 0, sizeof(data));
    memset(temp, 0, sizeof(temp));

    auto err = uc_mem_read(uc, STACK_ADDRESS, temp, STACK_SIZE);
    if (err) {
        LOG_ERROR("Failed to read memory. Address: " << std::hex << STACK_ADDRESS);
        tinyfd_messageBox("ERROR!", "Failed to read memory!!", "ok", "error", 0);
        return;
    }

    copyBigEndian(data, temp, STACK_SIZE);

    stackEditor.DrawWindow("Stack", (void*)((uintptr_t)data), STACK_SIZE);
    ImGui::PopFont();
}
