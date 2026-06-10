#pragma once

#include <cstdint>
#include <string>

bool isElfBinaryFile(const std::string& path);
bool loadElfBinaryForDebug(const std::string& path);
bool reloadElfBinaryForDebug();
bool localElfBinaryLoaded();
bool syncLocalElfDisassemblyView(uint64_t currentPc, bool force = false);
void clearLocalElfBinary();
