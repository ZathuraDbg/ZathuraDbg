#include "debugState.hpp"

#include "debugBackend.hpp"
#include "gdb/gdbRemote.hpp"
#include "interpreter/interpreter.hpp"

#include <algorithm>
#include <iomanip>
#include <map>
#include <sstream>
#include <string_view>
#include <unordered_map>

extern void consoleWriteThreadSafe(const std::string& text);

namespace {

constexpr size_t kMaxRegisterChanges = 64;
constexpr size_t kMaxMemoryChanges = 128;

std::vector<DebugWatchpoint> g_watchpoints;
std::vector<DebugRegisterChange> g_registerChanges;
std::vector<DebugMemoryChange> g_memoryChanges;
std::vector<DebugMemoryChange> g_stackMemoryChanges;
tsl::ordered_map<std::string, std::string> g_previousRegisters;
std::unordered_map<uint64_t, uint8_t> g_previousMemory;
std::unordered_map<uint64_t, uint8_t> g_previousStackMemory;

std::string formatAddress(const uint64_t address) {
    std::ostringstream out;
    out << "0x" << std::hex << address;
    return out.str();
}

int remoteWatchpointType(const WatchpointKind kind) {
    switch (kind) {
        case WatchpointKind::Write: return 2;
        case WatchpointKind::Read: return 3;
        case WatchpointKind::Access: return 4;
    }
    return 2;
}

bool sendRemoteWatchpointPacket(const char prefix, const DebugWatchpoint& watchpoint) {
    std::ostringstream packet;
    packet << prefix << remoteWatchpointType(watchpoint.kind)
           << "," << std::hex << watchpoint.address
           << "," << std::hex << watchpoint.size;

    std::string response;
    return remote_gdb::remoteSendRawPacket(packet.str(), response) && response == "OK";
}

bool rangesOverlap(const uint64_t aStart, const uint64_t aSize,
                   const uint64_t bStart, const uint64_t bSize) {
    const uint64_t aEnd = aStart + aSize;
    const uint64_t bEnd = bStart + bSize;
    return aStart < bEnd && bStart < aEnd;
}

void noteWatchpointHit(const uint64_t address, const char* access) {
    for (auto& watchpoint : g_watchpoints) {
        if (!watchpoint.enabled ||
            !rangesOverlap(address, 1, watchpoint.address, watchpoint.size)) {
            continue;
        }

        const bool readHit = std::string_view(access) == "read";
        const bool writeHit = std::string_view(access) == "write";
        if ((readHit && watchpoint.kind == WatchpointKind::Write) ||
            (writeHit && watchpoint.kind == WatchpointKind::Read)) {
            continue;
        }

        ++watchpoint.hitCount;
        watchpoint.lastHitAddress = address;
        watchpoint.lastAccess = access;
        consoleWriteThreadSafe("watchpoint >> " + std::string(access) + " at " +
                               formatAddress(address) + " matched " +
                               formatAddress(watchpoint.address) + "\n");
    }
}

void watchReadHook(void*, const uint64_t address, uint8_t, const uint8_t*) {
    noteWatchpointHit(address, "read");
}

void watchWriteHook(void*, const uint64_t address, uint8_t, uint64_t) {
    noteWatchpointHit(address, "write");
}

void trackMemoryRange(const uint64_t baseAddress,
                      const std::vector<uint8_t>& bytes,
                      std::unordered_map<uint64_t, uint8_t>& previousBytes,
                      std::vector<DebugMemoryChange>& visibleChanges) {
    std::vector<DebugMemoryChange> changes;
    for (size_t offset = 0; offset < bytes.size(); ++offset) {
        const uint64_t address = baseAddress + offset;
        const auto previous = previousBytes.find(address);
        if (previous != previousBytes.end() && previous->second != bytes[offset]) {
            changes.push_back({address, previous->second, bytes[offset]});
            if (changes.size() >= kMaxMemoryChanges) {
                break;
            }
        }
    }

    if (!changes.empty()) {
        visibleChanges = std::move(changes);
    }
    previousBytes.clear();
    for (size_t offset = 0; offset < bytes.size(); ++offset) {
        previousBytes[baseAddress + offset] = bytes[offset];
    }
}

}

const char* watchpointKindName(const WatchpointKind kind) {
    switch (kind) {
        case WatchpointKind::Write: return "write";
        case WatchpointKind::Read: return "read";
        case WatchpointKind::Access: return "access";
    }
    return "write";
}

WatchpointKind watchpointKindFromName(const std::string& name) {
    if (name == "read" || name == "rwatch") {
        return WatchpointKind::Read;
    }
    if (name == "access" || name == "awatch") {
        return WatchpointKind::Access;
    }
    return WatchpointKind::Write;
}

bool addDebugWatchpoint(const uint64_t address, size_t size, const WatchpointKind kind) {
    if (address == 0) {
        return false;
    }
    if (size == 0) {
        size = 1;
    }

    const auto existing = std::ranges::find_if(g_watchpoints, [&](const DebugWatchpoint& watchpoint) {
        return watchpoint.address == address && watchpoint.size == size && watchpoint.kind == kind;
    });
    if (existing != g_watchpoints.end()) {
        return false;
    }

    DebugWatchpoint watchpoint;
    watchpoint.address = address;
    watchpoint.size = size;
    watchpoint.kind = kind;

    if (remote_gdb::useRemoteDebugging() && remote_gdb::remoteDebugConnected()) {
        if (!sendRemoteWatchpointPacket('Z', watchpoint)) {
            return false;
        }
    }

    g_watchpoints.push_back(watchpoint);
    installDebugWatchpointHooks();
    return true;
}

bool removeDebugWatchpoint(const size_t index) {
    if (index >= g_watchpoints.size()) {
        return false;
    }

    auto& watchpoint = g_watchpoints[index];
    if (remote_gdb::useRemoteDebugging() && remote_gdb::remoteDebugConnected()) {
        sendRemoteWatchpointPacket('z', watchpoint);
    }

    if (icicle != nullptr) {
        if (watchpoint.readHookId != 0) {
            icicle_remove_mem_read_hook(icicle, watchpoint.readHookId);
        }
        if (watchpoint.writeHookId != 0) {
            icicle_remove_mem_write_hook(icicle, watchpoint.writeHookId);
        }
    }

    g_watchpoints.erase(g_watchpoints.begin() + static_cast<std::ptrdiff_t>(index));
    return true;
}

void clearDebugWatchpoints() {
    if (remote_gdb::useRemoteDebugging() && remote_gdb::remoteDebugConnected()) {
        for (const auto& watchpoint : g_watchpoints) {
            sendRemoteWatchpointPacket('z', watchpoint);
        }
    }
    resetDebugWatchpointHooks();
    g_watchpoints.clear();
}

std::vector<DebugWatchpoint>& mutableDebugWatchpoints() {
    return g_watchpoints;
}

const std::vector<DebugWatchpoint>& debugWatchpoints() {
    return g_watchpoints;
}

void installDebugWatchpointHooks() {
    if (remote_gdb::useRemoteDebugging() || icicle == nullptr) {
        return;
    }

    for (auto& watchpoint : g_watchpoints) {
        if (!watchpoint.enabled) {
            continue;
        }

        const uint64_t end = watchpoint.address + std::max<size_t>(watchpoint.size, 1);
        if ((watchpoint.kind == WatchpointKind::Read || watchpoint.kind == WatchpointKind::Access) &&
            watchpoint.readHookId == 0) {
            watchpoint.readHookId = icicle_add_mem_read_hook(icicle, watchReadHook, nullptr,
                                                             watchpoint.address, end);
        }
        if ((watchpoint.kind == WatchpointKind::Write || watchpoint.kind == WatchpointKind::Access) &&
            watchpoint.writeHookId == 0) {
            watchpoint.writeHookId = icicle_add_mem_write_hook(icicle, watchWriteHook, nullptr,
                                                              watchpoint.address, end);
        }
    }
}

void resetDebugWatchpointHooks() {
    if (icicle != nullptr) {
        for (auto& watchpoint : g_watchpoints) {
            if (watchpoint.readHookId != 0) {
                icicle_remove_mem_read_hook(icicle, watchpoint.readHookId);
            }
            if (watchpoint.writeHookId != 0) {
                icicle_remove_mem_write_hook(icicle, watchpoint.writeHookId);
            }
            watchpoint.readHookId = 0;
            watchpoint.writeHookId = 0;
        }
        return;
    }

    for (auto& watchpoint : g_watchpoints) {
        watchpoint.readHookId = 0;
        watchpoint.writeHookId = 0;
    }
}

void syncRemoteDebugWatchpoints() {
    if (!remote_gdb::useRemoteDebugging() || !remote_gdb::remoteDebugConnected()) {
        return;
    }

    for (const auto& watchpoint : g_watchpoints) {
        if (watchpoint.enabled) {
            sendRemoteWatchpointPacket('Z', watchpoint);
        }
    }
}

void trackDebugRegisters(const tsl::ordered_map<std::string, std::string>& values) {
    std::vector<DebugRegisterChange> changes;
    if (!g_previousRegisters.empty()) {
        for (const auto& [name, value] : values) {
            const auto previous = g_previousRegisters.find(name);
            if (previous == g_previousRegisters.end() || previous->second == value) {
                continue;
            }

            changes.push_back({name, previous->second, value});
            if (changes.size() >= kMaxRegisterChanges) {
                break;
            }
        }
    }

    if (!changes.empty()) {
        g_registerChanges = std::move(changes);
    }
    g_previousRegisters = values;
}

void trackDebugMemory(const uint64_t baseAddress, const std::vector<uint8_t>& bytes) {
    trackMemoryRange(baseAddress, bytes, g_previousMemory, g_memoryChanges);
}

void trackDebugStackMemory(const uint64_t baseAddress, const std::vector<uint8_t>& bytes) {
    trackMemoryRange(baseAddress, bytes, g_previousStackMemory, g_stackMemoryChanges);
}

void clearVisibleDebugDiffs() {
    g_registerChanges.clear();
    g_memoryChanges.clear();
    g_stackMemoryChanges.clear();
}

void clearDebugDiffs() {
    g_registerChanges.clear();
    g_memoryChanges.clear();
    g_stackMemoryChanges.clear();
    g_previousRegisters.clear();
    g_previousMemory.clear();
    g_previousStackMemory.clear();
}

bool isDebugMemoryChanged(const uint64_t address) {
    return std::ranges::any_of(g_memoryChanges, [&](const DebugMemoryChange& change) {
        return change.address == address;
    });
}

bool isDebugStackMemoryChanged(const uint64_t address) {
    return std::ranges::any_of(g_stackMemoryChanges, [&](const DebugMemoryChange& change) {
        return change.address == address;
    });
}

const std::vector<DebugRegisterChange>& debugRegisterChanges() {
    return g_registerChanges;
}

const std::vector<DebugMemoryChange>& debugMemoryChanges() {
    return g_memoryChanges;
}

const std::vector<DebugMemoryChange>& debugStackMemoryChanges() {
    return g_stackMemoryChanges;
}
