#pragma once

#include <cstdint>
#include <map>
#include <string>

namespace remote_gdb {

struct ElfSymbols {
    std::map<uint64_t, std::string> addrToName;
};

ElfSymbols loadElfSymbols(const std::string& path);

}
