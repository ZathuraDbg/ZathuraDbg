#include "elfSymbols.hpp"

#ifdef _WIN32

namespace remote_gdb {

ElfSymbols loadElfSymbols(const std::string&) {
    return {};
}

}

#else

#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstring>

namespace remote_gdb {

ElfSymbols loadElfSymbols(const std::string& path) {
    ElfSymbols result;

    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return result;

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return result;
    }

    void* data = mmap(nullptr, static_cast<size_t>(st.st_size), PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (data == MAP_FAILED) return result;

    auto* ehdr = reinterpret_cast<Elf64_Ehdr*>(data);
    if (std::memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        munmap(data, static_cast<size_t>(st.st_size));
        return result;
    }

    const bool is64 = (ehdr->e_ident[EI_CLASS] == ELFCLASS64);
    const char* shstrtab = nullptr;
    size_t shnum = 0;
    void* shdrBase = nullptr;

    if (is64) {
        shdrBase = reinterpret_cast<char*>(data) + ehdr->e_shoff;
        shnum = ehdr->e_shnum;
        auto* shdr = reinterpret_cast<Elf64_Shdr*>(shdrBase);
        shstrtab = reinterpret_cast<const char*>(data) + shdr[ehdr->e_shstrndx].sh_offset;
    } else {
        auto* ehdr32 = reinterpret_cast<Elf32_Ehdr*>(data);
        shdrBase = reinterpret_cast<char*>(data) + ehdr32->e_shoff;
        shnum = ehdr32->e_shnum;
        auto* shdr = reinterpret_cast<Elf32_Shdr*>(shdrBase);
        shstrtab = reinterpret_cast<const char*>(data) + shdr[ehdr32->e_shstrndx].sh_offset;
    }

    for (size_t i = 0; i < shnum; ++i) {
        const char* secName = nullptr;
        uint64_t secSize = 0;
        uint64_t secOff = 0;
        uint64_t secEntsize = 0;
        uint64_t secLink = 0;

        if (is64) {
            auto* shdr = reinterpret_cast<Elf64_Shdr*>(shdrBase);
            secName = shstrtab + shdr[i].sh_name;
            secSize = shdr[i].sh_size;
            secOff  = shdr[i].sh_offset;
            secEntsize = shdr[i].sh_entsize;
            secLink = shdr[i].sh_link;
        } else {
            auto* shdr = reinterpret_cast<Elf32_Shdr*>(shdrBase);
            secName = shstrtab + shdr[i].sh_name;
            secSize = shdr[i].sh_size;
            secOff  = shdr[i].sh_offset;
            secEntsize = shdr[i].sh_entsize;
            secLink = shdr[i].sh_link;
        }

        if (std::strcmp(secName, ".symtab") != 0 && std::strcmp(secName, ".dynsym") != 0) continue;

        const char* strtab = nullptr;
        if (is64) {
            auto* shdr = reinterpret_cast<Elf64_Shdr*>(shdrBase);
            strtab = reinterpret_cast<const char*>(data) + shdr[secLink].sh_offset;
        } else {
            auto* shdr = reinterpret_cast<Elf32_Shdr*>(shdrBase);
            strtab = reinterpret_cast<const char*>(data) + shdr[secLink].sh_offset;
        }

        const size_t count = secEntsize > 0 ? secSize / secEntsize : 0;
        auto* symBase = reinterpret_cast<char*>(data) + secOff;

        for (size_t j = 0; j < count; ++j) {
            uint64_t symVal = 0;
            uint64_t symSizeVal = 0;
            uint8_t symType = 0;
            uint16_t symShndx = 0;
            const char* symName = nullptr;

            if (is64) {
                auto* sym = reinterpret_cast<Elf64_Sym*>(symBase) + j;
                symVal  = sym->st_value;
                symSizeVal = sym->st_size;
                symType = ELF64_ST_TYPE(sym->st_info);
                symShndx = sym->st_shndx;
                if (sym->st_name > 0) symName = strtab + sym->st_name;
            } else {
                auto* sym = reinterpret_cast<Elf32_Sym*>(symBase) + j;
                symVal  = sym->st_value;
                symSizeVal = sym->st_size;
                symType = ELF32_ST_TYPE(sym->st_info);
                symShndx = sym->st_shndx;
                if (sym->st_name > 0) symName = strtab + sym->st_name;
            }

            if (symVal == 0 || symShndx == SHN_UNDEF || symName == nullptr) continue;
            if (symType != STT_FUNC && symType != STT_NOTYPE) continue;
            if (symType == STT_NOTYPE && symSizeVal == 0) continue;
            if (result.addrToName.find(symVal) != result.addrToName.end()) continue;

            result.addrToName[symVal] = symName;
        }
    }

    munmap(data, static_cast<size_t>(st.st_size));
    return result;
}

}

#endif
