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

void stackWriteFunc(ImU8* data, const size_t offset, const ImU8 delta) {
    LOG_INFO("Stack is being written to...");
    auto err = uc_mem_write(uc, STACK_ADDRESS + STACK_SIZE - offset - 1, &delta, 1);

    if (err) {
        LOG_ERROR("Failed to write to memory. Address: " << std::hex << STACK_ADDRESS + offset);
        tinyfd_messageBox("ERROR!", "Failed to write to the memory address!!", "ok", "error", 0);
    }

    char hex[90];
    snprintf(hex, sizeof(hex), "Data change after stack operation: %x", delta);
    LOG_DEBUG(hex);
}

uint64_t stackErrorAddr = 0;
bool showPopupError = false;
bool stackErrorPopup(){
   bool map= tinyfd_messageBox("Stack in unmapped memory!", "The stack value you have set is not mapped by default. Do you want to map it?", "okcancel", "error", 0);
   if (map)
    {
        uc_mem_map(uc, STACK_ADDRESS, STACK_SIZE, UC_PROT_ALL);
        showPopupError = false;
       return true;
    }

    return false;
}

void stackEditorWindow() {
    const auto io = ImGui::GetIO();
    ImGui::PushFont(io.Fonts->Fonts[3]);
  
    if (!uc) {
        ImGui::PopFont();
        return;
    }

    static char data[5 * 1024 * 1024];
    static char temp[5 * 1024 * 1024];

    memset(data, 0, sizeof(data));
    memset(temp, 0, sizeof(temp));

    const auto err = uc_mem_read(uc, STACK_ADDRESS, temp, STACK_SIZE);
    if ((err == UC_ERR_READ_UNMAPPED) && ((STACK_ADDRESS != 0) && (!showPopupError))) {
        LOG_ERROR("Failed to read memory. Address: " << std::hex << STACK_ADDRESS);
        stackErrorAddr = STACK_ADDRESS;
        showPopupError = true;
        ImGui::PopFont();
        return;
    }

    if (showPopupError){
        if (!stackErrorPopup()) {
            STACK_ADDRESS = DEFAULT_STACK_ADDRESS;
            if (!isCodeRunning) {
                tempRegisterValueMap[getArchSBPStr(codeInformation.mode).first] = "0x00";
            }
        }
        showPopupError = false;
    }
    // if (isCodeRunning) {
        copyBigEndian(data, temp, STACK_SIZE);
    // }

    stackEditor.HighlightColor = ImColor(59, 60, 79);
    stackEditor.OptShowAddWindowButton = false;
    stackEditor.OptShowSetBaseAddrOption = true;
    stackEditor.OptFillMemoryRange = true;
    stackEditor.FillMemoryRange = fillMemoryWithBytePopup;
    stackEditor.StackFashionAddrSubtraction = true;

    stackEditor.DrawWindow("Stack", reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(data)), STACK_SIZE, STACK_ADDRESS + STACK_SIZE);
    ImGui::PopFont();
}
