#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>
#include <vector>
#include "icicle.h"

std::optional<std::vector<uint8_t>> readDebugMemory(uint64_t address, size_t size);
bool writeDebugMemory(uint64_t address, uint8_t byte);
std::vector<MemRegionInfo> debugMemoryRegions();
bool protectDebugMemory(uint64_t address, size_t size, MemoryProtection protection);
bool mapDebugMemory(uint64_t address, size_t size, MemoryProtection protection);
bool unmapDebugMemory(uint64_t address, size_t size);
