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

#include <cstddef>
#include <cstring>

namespace remote_gdb {

namespace {

bool rangeInFile(const uint64_t offset, const uint64_t size, const size_t fileSize) {
    return offset <= fileSize && size <= fileSize - offset;
}

const char* boundedString(const char* table, const uint64_t tableSize, const uint64_t offset) {
    if (offset >= tableSize) {
        return nullptr;
    }

    const char* start = table + offset;
    const void* terminator = std::memchr(start, '\0', static_cast<size_t>(tableSize - offset));
    return terminator ? start : nullptr;
}

}

ElfSymbols loadElfSymbols(const std::string& path) {
    ElfSymbols result;

    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return result;

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return result;
    }

    const auto fileSize = static_cast<size_t>(st.st_size);
    if (fileSize < EI_NIDENT) {
        close(fd);
        return result;
    }

    void* data = mmap(nullptr, fileSize, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (data == MAP_FAILED) return result;

    const auto* ident = static_cast<const unsigned char*>(data);
    if (std::memcmp(ident, ELFMAG, SELFMAG) != 0) {
        munmap(data, fileSize);
        return result;
    }

    const bool is64 = (ident[EI_CLASS] == ELFCLASS64);
    if (!is64 && ident[EI_CLASS] != ELFCLASS32) {
        munmap(data, fileSize);
        return result;
    }

    const char* shstrtab = nullptr;
    uint64_t shstrtabSize = 0;
    size_t shnum = 0;
    void* shdrBase = nullptr;

    if (is64) {
        if (fileSize < sizeof(Elf64_Ehdr)) {
            munmap(data, fileSize);
            return result;
        }

        auto* ehdr = reinterpret_cast<Elf64_Ehdr*>(data);
        if (ehdr->e_shentsize < sizeof(Elf64_Shdr) ||
            ehdr->e_shstrndx == SHN_UNDEF ||
            ehdr->e_shstrndx >= ehdr->e_shnum ||
            !rangeInFile(ehdr->e_shoff, static_cast<uint64_t>(ehdr->e_shnum) * ehdr->e_shentsize, fileSize)) {
            munmap(data, fileSize);
            return result;
        }

        shdrBase = reinterpret_cast<char*>(data) + ehdr->e_shoff;
        shnum = ehdr->e_shnum;
        auto* shdr = reinterpret_cast<Elf64_Shdr*>(shdrBase);
        const auto& shstr = shdr[ehdr->e_shstrndx];
        if (!rangeInFile(shstr.sh_offset, shstr.sh_size, fileSize)) {
            munmap(data, fileSize);
            return result;
        }

        shstrtab = reinterpret_cast<const char*>(data) + shstr.sh_offset;
        shstrtabSize = shstr.sh_size;
    } else {
        if (fileSize < sizeof(Elf32_Ehdr)) {
            munmap(data, fileSize);
            return result;
        }

        auto* ehdr32 = reinterpret_cast<Elf32_Ehdr*>(data);
        if (ehdr32->e_shentsize < sizeof(Elf32_Shdr) ||
            ehdr32->e_shstrndx == SHN_UNDEF ||
            ehdr32->e_shstrndx >= ehdr32->e_shnum ||
            !rangeInFile(ehdr32->e_shoff, static_cast<uint64_t>(ehdr32->e_shnum) * ehdr32->e_shentsize, fileSize)) {
            munmap(data, fileSize);
            return result;
        }

        shdrBase = reinterpret_cast<char*>(data) + ehdr32->e_shoff;
        shnum = ehdr32->e_shnum;
        auto* shdr = reinterpret_cast<Elf32_Shdr*>(shdrBase);
        const auto& shstr = shdr[ehdr32->e_shstrndx];
        if (!rangeInFile(shstr.sh_offset, shstr.sh_size, fileSize)) {
            munmap(data, fileSize);
            return result;
        }

        shstrtab = reinterpret_cast<const char*>(data) + shstr.sh_offset;
        shstrtabSize = shstr.sh_size;
    }

    for (size_t i = 0; i < shnum; ++i) {
        const char* secName = nullptr;
        uint64_t secSize = 0;
        uint64_t secOff = 0;
        uint64_t secEntsize = 0;
        uint64_t secLink = 0;

        if (is64) {
            auto* shdr = reinterpret_cast<Elf64_Shdr*>(shdrBase);
            secName = boundedString(shstrtab, shstrtabSize, shdr[i].sh_name);
            secSize = shdr[i].sh_size;
            secOff  = shdr[i].sh_offset;
            secEntsize = shdr[i].sh_entsize;
            secLink = shdr[i].sh_link;
        } else {
            auto* shdr = reinterpret_cast<Elf32_Shdr*>(shdrBase);
            secName = boundedString(shstrtab, shstrtabSize, shdr[i].sh_name);
            secSize = shdr[i].sh_size;
            secOff  = shdr[i].sh_offset;
            secEntsize = shdr[i].sh_entsize;
            secLink = shdr[i].sh_link;
        }

        if (secName == nullptr) continue;
        if (std::strcmp(secName, ".symtab") != 0 && std::strcmp(secName, ".dynsym") != 0) continue;
        if (secLink >= shnum || !rangeInFile(secOff, secSize, fileSize)) continue;

        const char* strtab = nullptr;
        uint64_t strtabSize = 0;
        if (is64) {
            auto* shdr = reinterpret_cast<Elf64_Shdr*>(shdrBase);
            if (!rangeInFile(shdr[secLink].sh_offset, shdr[secLink].sh_size, fileSize)) continue;
            strtab = reinterpret_cast<const char*>(data) + shdr[secLink].sh_offset;
            strtabSize = shdr[secLink].sh_size;
        } else {
            auto* shdr = reinterpret_cast<Elf32_Shdr*>(shdrBase);
            if (!rangeInFile(shdr[secLink].sh_offset, shdr[secLink].sh_size, fileSize)) continue;
            strtab = reinterpret_cast<const char*>(data) + shdr[secLink].sh_offset;
            strtabSize = shdr[secLink].sh_size;
        }

        const size_t minEntrySize = is64 ? sizeof(Elf64_Sym) : sizeof(Elf32_Sym);
        if (secEntsize < minEntrySize) continue;

        const size_t count = secEntsize > 0 ? secSize / secEntsize : 0;
        auto* symBase = reinterpret_cast<const char*>(data) + secOff;

        for (size_t j = 0; j < count; ++j) {
            const uint64_t entryOffset = secOff + (j * secEntsize);
            if (!rangeInFile(entryOffset, minEntrySize, fileSize)) continue;

            uint64_t symVal = 0;
            uint64_t symSizeVal = 0;
            uint8_t symType = 0;
            uint16_t symShndx = 0;
            const char* symName = nullptr;

            if (is64) {
                auto* sym = reinterpret_cast<const Elf64_Sym*>(symBase + (j * secEntsize));
                symVal  = sym->st_value;
                symSizeVal = sym->st_size;
                symType = ELF64_ST_TYPE(sym->st_info);
                symShndx = sym->st_shndx;
                if (sym->st_name > 0) symName = boundedString(strtab, strtabSize, sym->st_name);
            } else {
                auto* sym = reinterpret_cast<const Elf32_Sym*>(symBase + (j * secEntsize));
                symVal  = sym->st_value;
                symSizeVal = sym->st_size;
                symType = ELF32_ST_TYPE(sym->st_info);
                symShndx = sym->st_shndx;
                if (sym->st_name > 0) symName = boundedString(strtab, strtabSize, sym->st_name);
            }

            if (symVal == 0 || symShndx == SHN_UNDEF || symName == nullptr) continue;
            if (symType != STT_FUNC && symType != STT_NOTYPE) continue;
            if (symType == STT_NOTYPE && symSizeVal == 0) continue;
            if (result.addrToName.find(symVal) != result.addrToName.end()) continue;

            result.addrToName[symVal] = symName;
        }
    }

    munmap(data, fileSize);
    return result;
}

}

#endif
