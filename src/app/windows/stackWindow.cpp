#include "windows.hpp"
MemoryEditor stackEditor;

// Optimized big-endian copy using a more efficient algorithm
static void* copyBigEndian(void* dst, const void* src, size_t size)
{
    uint8_t* dst_ptr = static_cast<uint8_t*>(dst);
    const uint8_t* src_ptr = static_cast<const uint8_t*>(src) + size - 1;
    
    // Use 8-byte chunks to speed up copying when possible
    const size_t chunks = size / 8;
    const size_t remainder = size % 8;
    
    for (size_t i = 0; i < chunks; ++i) {
        for (size_t j = 0; j < 8; ++j) {
            *dst_ptr++ = *src_ptr--;
        }
    }
    
    // Handle remaining bytes
    for (size_t i = 0; i < remainder; ++i) {
        *dst_ptr++ = *src_ptr--;
    }
    
    return dst;
}

void stackWriteFunc(ImU8* data, const size_t offset, const ImU8 delta) {
    // Calculate address once
    const uint64_t address = STACK_ADDRESS + STACK_SIZE - offset - 1;
    
    LOG_INFO("Stack write at 0x" << std::hex << address << ": " << static_cast<int>(delta));
    
    // Write to memory
    const auto err = icicle_mem_write(icicle, address, &delta, 1);
    if (err == -1) {
        LOG_ERROR("Failed to write to memory. Address: 0x" << std::hex << address);
        tinyfd_messageBox("ERROR!", "Failed to write to the memory address!!", "ok", "error", 0);
        return;
    }
    
    // Memory successfully written, mark for update
    updateStack = true;
}

uint64_t stackErrorAddr = 0;
bool showPopupError = false;

// Improved error handling with proper return
bool handleStackError() {
    if (!showPopupError) return true;

    // const bool shouldMap = tinyfd_messageBox(
    //     "Stack in unmapped memory!",
    //     "The stack value you have set is not mapped by default. Do you want to map it?",
    //     "okcancel", "error", 0);

    if (1) {
        const auto result = icicle_mem_map(icicle, STACK_ADDRESS, STACK_SIZE, MemoryProtection::ReadWrite);
        if (result != 0) {
            LOG_INFO("Successfully mapped stack memory at 0x" << std::hex << STACK_ADDRESS);
            showPopupError = false;
            return true;
        } else {
            LOG_ERROR("Failed to map stack memory at 0x" << std::hex << STACK_ADDRESS);
        }
    }
    
    // Reset to default address if mapping failed or was declined
    STACK_ADDRESS = DEFAULT_STACK_ADDRESS;
    if (!isCodeRunning) {
        tempRegisterValueMap[archSPStr] = "0x00";
    }
    showPopupError = false;
    return false;
}

// Keep these as globals for compatibility with main.cpp
unsigned char* stackEditorData;
unsigned char* stackEditorTemp;
bool stackArraysZeroed = false;

void stackEditorWindow() {
    auto io = ImGui::GetIO();
    ImGui::PushFont(io.Fonts->Fonts[3]);

    // Initialize stack arrays if not already done
    if (!stackArraysZeroed) {
        LOG_INFO("Creating stack...");
        memset(stackEditorData, 0, STACK_SIZE);
        memset(stackEditorTemp, 0, STACK_SIZE);
        stackArraysZeroed = true;
    }

    // // Handle stack error if needed
    // if (showPopupError && !handleStackError()) {
    //     ImGui::PopFont();
    //     return;
    // }

    if (icicle)
    {
        static bool stack_mapped_once = false;
        if (!stack_mapped_once) {
            // Only try to map once per session, not every frame
            LOG_INFO("Stack mapping if not done already");

            // Try to read memory first to see if it's already mapped
            size_t test_size = 0;
            unsigned char* test_data = icicle_mem_read(icicle, STACK_ADDRESS, 1, &test_size);
            bool already_mapped = (test_data != nullptr);

            if (test_data) {
                icicle_free_buffer(test_data, test_size);
                LOG_INFO("Stack memory is already mapped");
            } else {
                LOG_INFO("Stack memory needs mapping");
                if (icicle_mem_map(icicle, STACK_ADDRESS, STACK_SIZE, ReadWrite) != 0) {
                    LOG_INFO("Successfully mapped stack memory");
                } else {
                    LOG_ERROR("Failed to map stack memory!");
                    ImGui::Text("Failed to map stack memory!");
                    ImGui::PopFont();
                    return;
                }
            }

            // Mark as mapped to avoid attempting again
            stack_mapped_once = true;
        }
    }
    size_t outSize = 0;
    auto memData = icicle_mem_read(icicle, STACK_ADDRESS, STACK_SIZE, &outSize);
    
    if (!memData) {
        if (!showPopupError) {
            // LOG_ERROR("Failed to read memory. Address: 0x" << std::hex << STACK_ADDRESS);
            memData = stackEditorTemp;
        }
    } else {
        if (updateStack) {
            copyBigEndian(stackEditorData, memData, STACK_SIZE);
            updateStack = false;
        }
    }

    // Configure memory editor
    stackEditor.HighlightColor = ImColor(59, 60, 79);
    stackEditor.OptShowAddWindowButton = false;
    stackEditor.OptFillMemoryRange = true;
    stackEditor.FillMemoryRange = fillMemoryWithBytePopup;
    stackEditor.StackFashionAddrSubtraction = true;

    // Draw the editor window
    stackEditor.DrawWindow("Stack", reinterpret_cast<void*>(stackEditorData), STACK_SIZE, STACK_ADDRESS + STACK_SIZE);

    if (!newMemEditWindows.empty()) {
        int i = 0;
        for (auto& [memEditor, address, size]: newMemEditWindows){
            size_t newMemSize = 0;
            unsigned char* newMemData = icicle_mem_read(icicle, address, size, &newMemSize);
            if (newMemData == NULL)
            {
                memEditor.DrawWindow(("Memory Editor " + std::to_string(++i)).c_str(), (void*)zeroArr, 0x1000, address);
            }
            else
            {
                memEditor.DrawWindow(("Memory Editor " + std::to_string(++i)).c_str(), (void*)newMemData, size, address);
            }
        }
    }

    ImGui::PopFont();
}
