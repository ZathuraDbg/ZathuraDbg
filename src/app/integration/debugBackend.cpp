#include "debugBackend.hpp"
#include "gdb/gdbRemote.hpp"
#include "interpreter/interpreter.hpp"
#include "../../../vendor/icicle-cpp/icicle.h"

std::optional<std::vector<uint8_t>> readDebugMemory(const uint64_t address, const size_t size)
{
    if (remote_gdb::useRemoteDebugging()) {
        return remote_gdb::remoteReadMemory(address, size);
    }

    if (!icicle) return std::nullopt;

    size_t outSize = 0;
    unsigned char* raw = icicle_mem_read(icicle, address, size, &outSize);
    if (!raw) return std::nullopt;

    std::vector<uint8_t> result(raw, raw + outSize);
    icicle_free_buffer(raw, outSize);
    return result;
}

bool writeDebugMemory(const uint64_t address, const uint8_t byte)
{
    if (remote_gdb::useRemoteDebugging()) {
        return remote_gdb::remoteWriteMemory(address, {byte});
    }

    if (!icicle) return false;
    return icicle_mem_write(icicle, address, &byte, 1) != -1;
}
