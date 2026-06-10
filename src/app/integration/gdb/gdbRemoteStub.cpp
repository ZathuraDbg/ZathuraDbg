// Emscripten/wasm build stub for the GDB remote-debugging backend.
//
// The browser build has no raw TCP sockets and intentionally drops remote
// debugging entirely, but many call sites across the app reference the
// `remote_gdb::` API. This file provides inert implementations so the rest of
// the program links and behaves as if remote debugging is permanently
// unavailable (emulation-only). It replaces gdbRemote.cpp + gdbPacket.cpp in
// the wasm build.

#include "gdbRemote.hpp"

namespace remote_gdb {

DebugTargetMode debugTargetMode = DebugTargetMode::Emulation;
RemoteConnectionConfig remoteConnectionConfig{};

void setRemoteLogSink(RemoteLogSink) {}
void setRemoteArchHook(RemoteArchHook) {}

bool useRemoteDebugging() { return false; }
bool remoteDebugConnected() { return false; }
void remoteClearCachedState() {}

bool connectRemoteDebugSession() { return false; }
void disconnectRemoteDebugSession() {}
bool remoteRestartSession() { return false; }

bool remotePause() { return false; }
bool remoteContinue() { return false; }
bool remoteStep() { return false; }
bool remoteStepOver() { return false; }
bool remoteRefreshState() { return false; }

std::optional<std::vector<uint8_t>> remoteReadRegister(const std::string&) { return std::nullopt; }
bool remoteWriteRegister(const std::string&, const std::vector<uint8_t>&) { return false; }

std::optional<std::vector<uint8_t>> remoteReadMemory(uint64_t, size_t) { return std::nullopt; }
std::optional<std::vector<uint8_t>> remoteReadMemoryWithFallback(uint64_t, size_t) { return std::nullopt; }
bool remoteWriteMemory(uint64_t, const std::vector<uint8_t>&) { return false; }

bool remoteAddBreakpoint(uint64_t) { return false; }
bool remoteRemoveBreakpoint(uint64_t) { return false; }

std::vector<RemoteMemoryRegion> remoteMemoryRegions() { return {}; }
bool remoteTargetSupportsMemoryMap() { return false; }
bool remoteTargetSupportsTargetXml() { return false; }
std::optional<RemoteDisassemblyView> remoteBuildDisassemblyView(size_t, std::optional<uint64_t>) {
    return std::nullopt;
}

std::optional<uint64_t> remoteProgramCounter() { return std::nullopt; }
std::optional<uint64_t> remoteStackPointer() { return std::nullopt; }

bool remoteSendMonitorCommand(const std::string&, std::string&) { return false; }
bool remoteSendRawPacket(const std::string&, std::string&) { return false; }

bool remoteLoadSymbolFile(const std::string&) { return false; }
const ElfSymbols& remoteLoadedSymbols() {
    static const ElfSymbols empty{};
    return empty;
}

std::string remoteConnectionLabel() { return "Emulation"; }
std::string remoteLastStopReason() { return {}; }

}  // namespace remote_gdb
