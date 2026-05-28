#include "gdbPacket.hpp"

#include <cctype>
#include <charconv>

namespace remote_gdb {

std::string formatHexByte(const uint8_t byte) {
    constexpr char digits[] = "0123456789abcdef";
    std::string out(2, '0');
    out[0] = digits[(byte >> 4) & 0xf];
    out[1] = digits[byte & 0xf];
    return out;
}

std::string encodeHex(std::string_view input) {
    std::string out;
    out.reserve(input.size() * 2);
    for (const auto ch : input) {
        out += formatHexByte(static_cast<uint8_t>(ch));
    }
    return out;
}

std::string encodeHex(const std::vector<uint8_t>& input) {
    std::string out;
    out.reserve(input.size() * 2);
    for (const auto byte : input) {
        out += formatHexByte(byte);
    }
    return out;
}

std::optional<std::vector<uint8_t>> decodeHexBytes(std::string_view input) {
    std::string expanded;
    expanded.reserve(input.size());
    for (size_t i = 0; i < input.size(); ++i) {
        const auto ch = input[i];
        if (ch == '*' && !expanded.empty() && (i + 1) < input.size()) {
            const int repeatCount = static_cast<unsigned char>(input[++i]) - 29;
            if (repeatCount < 3 || repeatCount > 97) {
                return std::nullopt;
            }
            expanded.append(static_cast<size_t>(repeatCount), expanded.back());
            continue;
        }
        expanded.push_back(ch);
    }
    input = expanded;

    if ((input.size() % 2) != 0) {
        return std::nullopt;
    }

    std::vector<uint8_t> out;
    out.reserve(input.size() / 2);
    for (size_t i = 0; i < input.size(); i += 2) {
        const auto hi = input.substr(i, 2);
        unsigned int value = 0;
        auto result = std::from_chars(hi.data(), hi.data() + hi.size(), value, 16);
        if (result.ec != std::errc{}) {
            return std::nullopt;
        }
        out.push_back(static_cast<uint8_t>(value));
    }

    return out;
}

bool isHexString(std::string_view input) {
    for (const auto ch : input) {
        if (!std::isxdigit(static_cast<unsigned char>(ch))) {
            return false;
        }
    }
    return true;
}

std::string decodeHexText(std::string_view input) {
    const auto bytes = decodeHexBytes(input);
    if (!bytes.has_value()) {
        return {};
    }
    return {bytes->begin(), bytes->end()};
}

uint8_t packetChecksum(std::string_view payload) {
    uint8_t checksum = 0;
    for (const auto ch : payload) {
        checksum = static_cast<uint8_t>(checksum + static_cast<uint8_t>(ch));
    }
    return checksum;
}

}
