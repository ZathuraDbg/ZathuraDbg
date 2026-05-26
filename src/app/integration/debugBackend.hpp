#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>
#include <vector>

std::optional<std::vector<uint8_t>> readDebugMemory(uint64_t address, size_t size);
bool writeDebugMemory(uint64_t address, uint8_t byte);
