#include "integration/gdb/elfSymbols.hpp"

#include <elf.h>

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
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

std::vector<uint8_t> malformedElf64WithUnexpectedSectionEntrySize()
{
    std::vector<uint8_t> bytes(sizeof(Elf64_Ehdr) + sizeof(Elf64_Shdr) + 8, 0);
    auto* header = reinterpret_cast<Elf64_Ehdr*>(bytes.data());
    header->e_ident[EI_MAG0] = ELFMAG0;
    header->e_ident[EI_MAG1] = ELFMAG1;
    header->e_ident[EI_MAG2] = ELFMAG2;
    header->e_ident[EI_MAG3] = ELFMAG3;
    header->e_ident[EI_CLASS] = ELFCLASS64;
    header->e_shoff = sizeof(Elf64_Ehdr);
    header->e_shentsize = sizeof(Elf64_Shdr) + 8;
    header->e_shnum = 1;
    header->e_shstrndx = 0;
    return bytes;
}

std::string shellQuote(const std::filesystem::path& path)
{
    std::string quoted = "'";
    for (const char c : path.string())
    {
        if (c == '\'')
        {
            quoted += "'\\''";
        }
        else
        {
            quoted += c;
        }
    }
    quoted += "'";
    return quoted;
}

bool expectSourceLinesFromDebugElf()
{
    const auto sourcePath = std::filesystem::temp_directory_path() / "zathura-source-lines-fixture.c";
    const auto elfPath = std::filesystem::temp_directory_path() / "zathura-source-lines-fixture";

    {
        std::ofstream source(sourcePath, std::ios::trunc);
        source << "static int add_one(int x) { return x + 1; }\n"
               << "int main(void) { return add_one(2); }\n";
    }

    const std::string command = "cc -g -O0 -o " + shellQuote(elfPath) + " " + shellQuote(sourcePath);
    if (std::system(command.c_str()) != 0)
    {
        std::cerr << "Failed to compile source-line fixture\n";
        std::filesystem::remove(sourcePath);
        return false;
    }

    const auto symbols = remote_gdb::loadElfSymbols(elfPath.string());
    std::filesystem::remove(sourcePath);
    std::filesystem::remove(elfPath);

    if (symbols.addrToSourceLine.empty())
    {
        std::cerr << "Expected source line entries from a debug ELF\n";
        return false;
    }

    for (const auto& [address, location] : symbols.addrToSourceLine)
    {
        if (address != 0 &&
            location.line > 0 &&
            std::filesystem::path(location.file).filename() == sourcePath.filename())
        {
            return true;
        }
    }

    std::cerr << "Expected at least one source line entry for " << sourcePath.filename() << '\n';
    return false;
}

}

int main()
{
    bool ok = true;
    ok &= expectNoSymbols("zathura-empty-elf-fixture", {});
    ok &= expectNoSymbols("zathura-short-elf-fixture", {ELFMAG0, ELFMAG1, ELFMAG2});
    ok &= expectNoSymbols("zathura-malformed-elf64-fixture", malformedElf64WithOutOfRangeSections());
    ok &= expectNoSymbols("zathura-oversized-shentsize-elf64-fixture",
                          malformedElf64WithUnexpectedSectionEntrySize());
    ok &= expectSourceLinesFromDebugElf();
    return ok ? 0 : 1;
}
