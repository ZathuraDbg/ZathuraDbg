#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace remote_gdb {

std::string formatHexByte(uint8_t byte);
std::string encodeHex(std::string_view input);
std::string encodeHex(const std::vector<uint8_t>& input);
std::optional<std::vector<uint8_t>> decodeHexBytes(std::string_view input);
bool isHexString(std::string_view input);
std::string decodeHexText(std::string_view input);
uint8_t packetChecksum(std::string_view payload);

}
