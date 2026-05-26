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
    {
        std::lock_guard<std::mutex> lk(debugReadyMutex);
    }

    const uint64_t address = STACK_ADDRESS + STACK_SIZE - offset - 1;
    LOG_INFO("Stack write at 0x" << std::hex << address << ": " << static_cast<int>(delta));

    bool writeOk = false;
    if (remote_gdb::useRemoteDebugging()) {
        writeOk = remote_gdb::remoteWriteMemory(address, {delta});
    } else {
        writeOk = icicle_mem_write(icicle, address, &delta, 1) != -1;
    }

    if (!writeOk) {
        LOG_ERROR("Failed to write to memory. Address: 0x" << std::hex << address);
        tinyfd_messageBox("ERROR!", "Failed to write to the memory address!!", "ok", "error", 0);
        return;
    }
    
    // Memory successfully written, mark for update
    updateStack = true;
}

uint64_t stackErrorAddr = 0;
bool showPopupError = false;

bool handleStackError() {
    if (!showPopupError) return true;

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

static std::unique_ptr<unsigned char[], decltype(&free)> stackBuffer(nullptr, free);
unsigned char* stackEditorData;
unsigned char* stackEditorTemp;

void stackEditorWindow() {
    const auto io = ImGui::GetIO();
    ImGui::PushFont(io.Fonts->Fonts[3]);

    // Initialize our buffer if not already done
    if (!stackBuffer) {
        stackBuffer.reset(static_cast<unsigned char*>(calloc(1, STACK_SIZE)));
    }

    // if (stackBuffer == nullptr) {
    //     stackBuffer = static_cast<unsigned char*>(calloc(1, STACK_SIZE));
    //     if (!stackBuffer) {
    //         LOG_ERROR("Failed to allocate stack buffer");
    //         ImGui::PopFont();
    //         return;
    //     }
    // }

    if (!remote_gdb::useRemoteDebugging() && icicle && isDebugReady)
    {
        static bool stack_mapped_once = false;
        if (!stack_mapped_once) {
            LOG_INFO("Stack mapping if not done already");

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
    unsigned char* memData = NULL;
    static size_t remoteStackReadable = 0;
    static uintptr_t lastStackAddr = 0;
    static bool remoteStackProbeFailed = false;

    if (lastStackAddr != STACK_ADDRESS) {
        remoteStackReadable = 0;
        lastStackAddr = STACK_ADDRESS;
        remoteStackProbeFailed = false;
    }

    if (isDebugReady)
    {
        if (remote_gdb::useRemoteDebugging()) {
            if (!remoteStackProbeFailed) {
                if (remoteStackReadable > 0) {
                    const auto remoteBytes = remote_gdb::remoteReadMemory(STACK_ADDRESS, remoteStackReadable);
                    if (remoteBytes.has_value()) {
                        outSize = remoteBytes->size();
                        memData = static_cast<unsigned char*>(malloc(outSize));
                        if (memData) {
                            memcpy(memData, remoteBytes->data(), outSize);
                        }
                    } else {
                        remoteStackReadable = 0;
                    }
                }

                if (!memData && remoteStackReadable == 0) {
                    static constexpr size_t fallbackSizes[] = {0x4000, 0x2000, 0x1000, 0x800, 0x200, 0x100};
                    for (const auto trySize : fallbackSizes) {
                        const auto remoteBytes = remote_gdb::remoteReadMemory(STACK_ADDRESS, trySize);
                        if (remoteBytes.has_value()) {
                            outSize = remoteBytes->size();
                            remoteStackReadable = trySize;
                            memData = static_cast<unsigned char*>(malloc(outSize));
                            if (memData) {
                                memcpy(memData, remoteBytes->data(), outSize);
                            }
                            break;
                        }
                    }
                    if (!memData) {
                        remoteStackProbeFailed = true;
                    }
                }
            }
        } else {
            memData = icicle_mem_read(icicle, STACK_ADDRESS, STACK_SIZE, &outSize);
        }
    }

    const size_t displaySize = outSize > 0 ? outSize : STACK_SIZE;

    if (!memData) {
        memset(stackBuffer.get(), 0, STACK_SIZE);
    } else {
        memset(stackBuffer.get(), 0, STACK_SIZE);
        copyBigEndian(stackBuffer.get(), memData, outSize);
        if (remote_gdb::useRemoteDebugging()) {
            free(memData);
        } else {
            icicle_free_buffer(memData, outSize);
        }
    }

    stackEditor.HighlightColor = ImColor(59, 60, 79);
    stackEditor.OptShowAddWindowButton = false;
    stackEditor.OptFillMemoryRange = true;
    stackEditor.FillMemoryRange = fillMemoryWithBytePopup;
    stackEditor.StackFashionAddrSubtraction = true;
    stackEditor.WriteFn = &stackWriteFunc;

    stackEditor.DrawWindow("Stack", reinterpret_cast<void*>(stackBuffer.get()), displaySize, STACK_ADDRESS + displaySize);

    if (!newMemEditWindows.empty()) {
        int i = 0;
        for (auto& [memEditor, address, size]: newMemEditWindows){
            size_t newMemSize = 0;
            unsigned char* newMemData = nullptr;
            if (remote_gdb::useRemoteDebugging()) {
                if (const auto remoteBytes = remote_gdb::remoteReadMemory(address, size); remoteBytes.has_value()) {
                    newMemSize = remoteBytes->size();
                    newMemData = static_cast<unsigned char*>(malloc(newMemSize));
                    if (newMemData) {
                        memcpy(newMemData, remoteBytes->data(), newMemSize);
                    }
                }
            } else {
                newMemData = icicle_mem_read(icicle, address, size, &newMemSize);
            }
            if (newMemData == NULL)
            {
                memEditor.DrawWindow(("Memory Editor " + std::to_string(++i)).c_str(), (void*)zeroArr, 0x1000, address);
            }
            else
            {
                memEditor.DrawWindow(("Memory Editor " + std::to_string(++i)).c_str(), (void*)newMemData, size, address);
                if (remote_gdb::useRemoteDebugging()) {
                    free(newMemData);
                } else {
                    icicle_free_buffer(newMemData, newMemSize);
                }
            }
        }
    }
    // cleanupStackEditor();

    ImGui::PopFont();
}

// void cleanupStackEditor() {
//     if (stackBuffer) {
//         free(stackBuffer);
//         stackBuffer = nullptr;
//     }
// }
