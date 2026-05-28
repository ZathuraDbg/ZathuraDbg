#include "debugBackend.hpp"
#include "gdb/gdbRemote.hpp"
#include "interpreter/interpreter.hpp"
#include "../../../vendor/icicle-cpp/icicle.h"

namespace {

MemoryProtection remoteProtection(const remote_gdb::RemoteMemoryRegion& region)
{
    if (region.read && region.write && region.execute) {
        return ExecuteReadWrite;
    }
    if (region.read && region.write) {
        return ReadWrite;
    }
    if (region.read && region.execute) {
        return ExecuteRead;
    }
    if (region.execute) {
        return ExecuteOnly;
    }
    if (region.read) {
        return ReadOnly;
    }
    return NoAccess;
}

}

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

std::vector<MemRegionInfo> debugMemoryRegions()
{
    if (remote_gdb::useRemoteDebugging()) {
        std::vector<MemRegionInfo> regions;
        for (const auto& region : remote_gdb::remoteMemoryRegions()) {
            regions.push_back({region.start, region.end - region.start, remoteProtection(region)});
        }
        return regions;
    }

    if (!icicle) return {};

    size_t count = 0;
    MemRegionInfo* rawRegions = icicle_mem_list_mapped(icicle, &count);
    if (!rawRegions) return {};

    std::vector<MemRegionInfo> regions(rawRegions, rawRegions + count);
    icicle_mem_list_mapped_free(rawRegions, count);
    return regions;
}

bool protectDebugMemory(const uint64_t address, const size_t size, const MemoryProtection protection)
{
    if (remote_gdb::useRemoteDebugging() || !icicle) return false;
    return icicle_mem_protect(icicle, address, size, protection) == 0;
}

bool mapDebugMemory(const uint64_t address, const size_t size, const MemoryProtection protection)
{
    if (remote_gdb::useRemoteDebugging() || !icicle) return false;
    return icicle_mem_map(icicle, address, size, protection) == 0;
}

bool unmapDebugMemory(const uint64_t address, const size_t size)
{
    if (remote_gdb::useRemoteDebugging() || !icicle) return false;
    return icicle_mem_unmap(icicle, address, size) == 0;
}
