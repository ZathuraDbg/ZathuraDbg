#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <tsl/ordered_map.h>

enum class WatchpointKind {
    Write = 0,
    Read = 1,
    Access = 2,
};

struct DebugRegisterChange {
    std::string name;
    std::string before;
    std::string after;
};

struct DebugMemoryChange {
    uint64_t address = 0;
    uint8_t before = 0;
    uint8_t after = 0;
};

struct DebugWatchpoint {
    uint64_t address = 0;
    size_t size = 1;
    WatchpointKind kind = WatchpointKind::Write;
    bool enabled = true;
    uint64_t hitCount = 0;
    uint64_t lastHitAddress = 0;
    std::string lastAccess;
    uint32_t readHookId = 0;
    uint32_t writeHookId = 0;
};

const char* watchpointKindName(WatchpointKind kind);
WatchpointKind watchpointKindFromName(const std::string& name);

bool addDebugWatchpoint(uint64_t address, size_t size, WatchpointKind kind);
bool removeDebugWatchpoint(size_t index);
void clearDebugWatchpoints();
std::vector<DebugWatchpoint>& mutableDebugWatchpoints();
const std::vector<DebugWatchpoint>& debugWatchpoints();
void installDebugWatchpointHooks();
void resetDebugWatchpointHooks();
void syncRemoteDebugWatchpoints();

void trackDebugRegisters(const tsl::ordered_map<std::string, std::string>& values);
void trackDebugMemory(uint64_t baseAddress, const std::vector<uint8_t>& bytes);
void trackDebugStackMemory(uint64_t baseAddress, const std::vector<uint8_t>& bytes);
void clearVisibleDebugDiffs();
void clearDebugDiffs();
bool isDebugMemoryChanged(uint64_t address);
bool isDebugStackMemoryChanged(uint64_t address);
const std::vector<DebugRegisterChange>& debugRegisterChanges();
const std::vector<DebugMemoryChange>& debugMemoryChanges();
const std::vector<DebugMemoryChange>& debugStackMemoryChanges();
