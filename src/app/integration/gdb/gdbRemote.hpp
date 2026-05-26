#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "elfSymbols.hpp"

namespace remote_gdb {

enum class DebugTargetMode {
    Emulation = 0,
    RemoteGdb = 1,
};

struct RemoteConnectionConfig {
    std::string host = "127.0.0.1";
    uint16_t port = 1234;
};

struct RemoteMemoryRegion {
    uint64_t start = 0;
    uint64_t end = 0;
    bool read = false;
    bool write = false;
    bool execute = false;
};

struct RemoteDisassemblyView {
    uint64_t startAddress = 0;
    uint64_t currentAddress = 0;
    uint64_t currentLine = 0;
    std::string text;
    std::unordered_map<uint64_t, uint64_t> addressLineMap;
    std::map<int, std::string> lineAddressLabels;
    std::map<std::string, int> labelMap;
};

extern DebugTargetMode debugTargetMode;
extern RemoteConnectionConfig remoteConnectionConfig;

bool useRemoteDebugging();
bool remoteDebugConnected();
void remoteClearCachedState();

bool connectRemoteDebugSession();
void disconnectRemoteDebugSession();
bool remoteRestartSession();

bool remotePause();
bool remoteContinue();
bool remoteStep();
bool remoteStepOver();
bool remoteRefreshState();

std::optional<std::vector<uint8_t>> remoteReadRegister(const std::string& regName);
bool remoteWriteRegister(const std::string& regName, const std::vector<uint8_t>& bytes);

std::optional<std::vector<uint8_t>> remoteReadMemory(uint64_t address, size_t size);
bool remoteWriteMemory(uint64_t address, const std::vector<uint8_t>& bytes);

bool remoteAddBreakpoint(uint64_t address);
bool remoteRemoveBreakpoint(uint64_t address);

std::vector<RemoteMemoryRegion> remoteMemoryRegions();
bool remoteTargetSupportsMemoryMap();
bool remoteTargetSupportsTargetXml();
std::optional<RemoteDisassemblyView> remoteBuildDisassemblyView(
    size_t instructionCount = 64,
    std::optional<uint64_t> startAddress = std::nullopt);

std::optional<uint64_t> remoteProgramCounter();
std::optional<uint64_t> remoteStackPointer();

bool remoteSendMonitorCommand(const std::string& command, std::string& response);
bool remoteSendRawPacket(const std::string& payload, std::string& response);

bool remoteLoadSymbolFile(const std::string& path);
const ElfSymbols& remoteLoadedSymbols();

std::string remoteConnectionLabel();
std::string remoteLastStopReason();

}
