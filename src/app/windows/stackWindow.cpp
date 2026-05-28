#include "windows.hpp"
MemoryEditor stackEditor;

static void* copyBigEndian(void* dst, const void* src, size_t size)
{
    uint8_t* dst_ptr = static_cast<uint8_t*>(dst);
    const uint8_t* src_ptr = static_cast<const uint8_t*>(src) + size - 1;

    const size_t chunks = size / 8;
    const size_t remainder = size % 8;

    for (size_t i = 0; i < chunks; ++i) {
        for (size_t j = 0; j < 8; ++j) {
            *dst_ptr++ = *src_ptr--;
        }
    }

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

    const bool writeOk = writeDebugMemory(address, delta);

    if (!writeOk) {
        LOG_ERROR("Failed to write to memory. Address: 0x" << std::hex << address);
        tinyfd_messageBox("ERROR!", "Failed to write to the memory address!!", "ok", "error", 0);
        return;
    }

    updateStack = true;
}

uint64_t stackErrorAddr = 0;
bool showPopupError = false;

bool handleStackError() {
    if (!showPopupError) return true;

    if (1) {
        const auto result = icicle_mem_map(icicle, STACK_ADDRESS, STACK_SIZE, MemoryProtection::ReadWrite);
        if (result == 0) {
            LOG_INFO("Successfully mapped stack memory at 0x" << std::hex << STACK_ADDRESS);
            showPopupError = false;
            return true;
        } else {
            LOG_ERROR("Failed to map stack memory at 0x" << std::hex << STACK_ADDRESS);
        }
    }

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

    if (!stackBuffer) {
        stackBuffer.reset(static_cast<unsigned char*>(calloc(1, STACK_SIZE)));
    }

    if (!remote_gdb::useRemoteDebugging() && icicle && isDebugReady)
    {
        static bool stack_mapped_once = false;
        if (!stack_mapped_once) {
            LOG_INFO("Stack mapping if not done already");

            size_t test_size = 0;
            unsigned char* test_data = icicle_mem_read(icicle, STACK_ADDRESS, 1, &test_size);

            if (test_data) {
                icicle_free_buffer(test_data, test_size);
                LOG_INFO("Stack memory is already mapped");
            } else {
                LOG_INFO("Stack memory needs mapping");
                if (icicle_mem_map(icicle, STACK_ADDRESS, STACK_SIZE, ReadWrite) == 0) {
                    LOG_INFO("Successfully mapped stack memory");
                } else {
                    LOG_ERROR("Failed to map stack memory!");
                    ImGui::Text("Failed to map stack memory!");
                    ImGui::PopFont();
                    return;
                }
            }

            stack_mapped_once = true;
        }
    }

    std::optional<std::vector<uint8_t>> memData;
    static size_t remoteStackReadable = 0;
    static uintptr_t lastStackAddr = 0;
    static bool remoteStackProbeFailed = false;
    static uint64_t lastStackResumeGen = ~uint64_t{0};

    if (lastStackAddr != STACK_ADDRESS || lastStackResumeGen != remoteResumeGeneration) {
        remoteStackReadable = 0;
        lastStackAddr = STACK_ADDRESS;
        lastStackResumeGen = remoteResumeGeneration;
        remoteStackProbeFailed = false;
    }

    if (isDebugReady) {
        if (remote_gdb::useRemoteDebugging()) {
            if (!remoteStackProbeFailed) {
                const size_t trySize = remoteStackReadable > 0 ? remoteStackReadable : STACK_SIZE;
                memData = remote_gdb::remoteReadMemoryWithFallback(STACK_ADDRESS, trySize);
                if (memData.has_value()) {
                    remoteStackReadable = memData->size();
                } else {
                    remoteStackReadable = 0;
                    remoteStackProbeFailed = true;
                }
            }
        } else {
            memData = readDebugMemory(STACK_ADDRESS, STACK_SIZE);
        }
    }

    const size_t displaySize = memData.has_value() ? memData->size() : STACK_SIZE;

    memset(stackBuffer.get(), 0, STACK_SIZE);
    if (memData.has_value()) {
        copyBigEndian(stackBuffer.get(), memData->data(), memData->size());
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
            const auto newMemData = readDebugMemory(address, size);
            if (!newMemData.has_value()) {
                memEditor.DrawWindow(("Memory Editor " + std::to_string(++i)).c_str(), (void*)zeroArr, 0x1000, address);
            } else {
                memEditor.DrawWindow(("Memory Editor " + std::to_string(++i)).c_str(),
                    const_cast<void*>(static_cast<const void*>(newMemData->data())), size, address);
            }
        }
    }

    ImGui::PopFont();
}
