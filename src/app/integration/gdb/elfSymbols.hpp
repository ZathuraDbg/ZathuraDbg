#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>

namespace remote_gdb {

struct SourceLocation {
    std::string file;
    uint64_t line = 0;
    uint64_t column = 0;
};

struct ElfSymbols {
    std::map<uint64_t, std::string> addrToName;
    std::map<uint64_t, SourceLocation> addrToSourceLine;
};

ElfSymbols loadElfSymbols(const std::string& path);
std::optional<SourceLocation> findSourceLocationForAddress(const ElfSymbols& symbols, uint64_t address);

}
