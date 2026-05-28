#include "integration/gdb/elfSymbols.hpp"

#include <elf.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

namespace {

std::filesystem::path writeFixture(const std::string& name, const std::vector<uint8_t>& bytes)
{
    const auto path = std::filesystem::temp_directory_path() / name;
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return path;
}

bool expectNoSymbols(const std::string& name, const std::vector<uint8_t>& bytes)
{
    const auto path = writeFixture(name, bytes);
    const auto symbols = remote_gdb::loadElfSymbols(path.string());
    std::filesystem::remove(path);

    if (!symbols.addrToName.empty())
    {
        std::cerr << "Expected no symbols for " << name << '\n';
        return false;
    }

    return true;
}

std::vector<uint8_t> malformedElf64WithOutOfRangeSections()
{
    std::vector<uint8_t> bytes(sizeof(Elf64_Ehdr), 0);
    auto* header = reinterpret_cast<Elf64_Ehdr*>(bytes.data());
    header->e_ident[EI_MAG0] = ELFMAG0;
    header->e_ident[EI_MAG1] = ELFMAG1;
    header->e_ident[EI_MAG2] = ELFMAG2;
    header->e_ident[EI_MAG3] = ELFMAG3;
    header->e_ident[EI_CLASS] = ELFCLASS64;
    header->e_shoff = 0x1000;
    header->e_shentsize = sizeof(Elf64_Shdr);
    header->e_shnum = 1;
    header->e_shstrndx = 0;
    return bytes;
}

}

int main()
{
    bool ok = true;
    ok &= expectNoSymbols("zathura-empty-elf-fixture", {});
    ok &= expectNoSymbols("zathura-short-elf-fixture", {ELFMAG0, ELFMAG1, ELFMAG2});
    ok &= expectNoSymbols("zathura-malformed-elf64-fixture", malformedElf64WithOutOfRangeSections());
    return ok ? 0 : 1;
}
