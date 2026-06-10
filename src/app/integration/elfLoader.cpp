#include "elfLoader.hpp"

#include "debugState.hpp"
#include "gdb/gdbRemote.hpp"
#include "interpreter/interpreter.hpp"

#include "../app.hpp"

#ifndef _WIN32
#include <elf.h>
#endif

#include <algorithm>
#include <capstone/capstone.h>
#include <cstring>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <vector>

extern void instructionHook(void* userData, uint64_t address);
extern void stackWriteHook(void* data, uint64_t address, uint8_t size, uint64_t valueWritten);
extern int handleSyscalls(void* data, uint64_t syscall_nr, const SyscallArgs* args);

namespace {

constexpr uint64_t kPageSize = 0x1000;

uint64_t pageFloor(const uint64_t value) {
    return value & ~(kPageSize - 1);
}

uint64_t pageCeil(const uint64_t value) {
    return (value + kPageSize - 1) & ~(kPageSize - 1);
}

MemoryProtection segmentProtection(const uint32_t flags) {
    const bool read = (flags & PF_R) != 0;
    const bool write = (flags & PF_W) != 0;
    const bool execute = (flags & PF_X) != 0;

    if (read && write && execute) return ExecuteReadWrite;
    if (read && write) return ReadWrite;
    if (read && execute) return ExecuteRead;
    if (execute) return ExecuteOnly;
    if (read) return ReadOnly;
    return NoAccess;
}

std::string formatAddress(const uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}

bool readWholeFile(const std::string& path, std::vector<uint8_t>& bytes) {
    std::ifstream input(path, std::ios::binary);
    if (!input.good()) {
        return false;
    }

    input.seekg(0, std::ios::end);
    const auto size = input.tellg();
    if (size <= 0) {
        return false;
    }
    input.seekg(0, std::ios::beg);

    bytes.resize(static_cast<size_t>(size));
    input.read(reinterpret_cast<char*>(bytes.data()), size);
    return input.good();
}

bool rangeInFile(const uint64_t offset, const uint64_t size, const size_t fileSize) {
    return offset <= fileSize && size <= fileSize - offset;
}

bool mapSegment(const std::vector<uint8_t>& file,
                const uint64_t vaddr,
                const uint64_t fileOffset,
                const uint64_t fileSize,
                const uint64_t memSize,
                const uint32_t flags) {
    if (memSize == 0 || !rangeInFile(fileOffset, fileSize, file.size())) {
        return false;
    }

    const uint64_t mapStart = pageFloor(vaddr);
    const uint64_t pageOffset = vaddr - mapStart;
    const uint64_t mapSize = pageCeil(pageOffset + memSize);
    const auto protection = segmentProtection(flags);

    if (icicle_mem_map(icicle, mapStart, mapSize, ExecuteReadWrite) != 0) {
        consoleWriteThreadSafe("elf >> failed to map segment at " + formatAddress(mapStart) + "\n");
        return false;
    }

    if (fileSize > 0 &&
        icicle_mem_write(icicle, vaddr, file.data() + fileOffset, static_cast<size_t>(fileSize)) != 0) {
        consoleWriteThreadSafe("elf >> failed to write segment at " + formatAddress(vaddr) + "\n");
        return false;
    }

    if (memSize > fileSize) {
        std::vector<uint8_t> zeros(static_cast<size_t>(memSize - fileSize), 0);
        icicle_mem_write(icicle, vaddr + fileSize, zeros.data(), zeros.size());
    }

    icicle_mem_protect(icicle, mapStart, mapSize, protection);
    return true;
}

std::optional<std::vector<uint8_t>> readEntryBytes(const uint64_t entry) {
    constexpr size_t sizes[] = {0x400, 0x200, 0x100, 0x80, 0x40, 0x20};
    for (const auto size : sizes) {
        if (auto bytes = readDebugMemory(entry, size); bytes.has_value() && !bytes->empty()) {
            return bytes;
        }
    }
    return std::nullopt;
}

void buildEntryDisassemblyView(const uint64_t entry) {
    const auto bytes = readEntryBytes(entry);
    if (!bytes.has_value() || bytes->empty()) {
        return;
    }

    csh handle{};
    if (cs_open(codeInformation.archCS, codeInformation.modeCS, &handle) != CS_ERR_OK) {
        return;
    }

    cs_insn* instructions = nullptr;
    const auto count = cs_disasm(handle, bytes->data(), bytes->size(), entry, 96, &instructions);
    if (count == 0 || instructions == nullptr) {
        cs_close(&handle);
        return;
    }

    std::ostringstream text;
    std::map<int, std::string> lineAddressLabels;
    std::map<int, std::string> lineOffsetLabels;
    const auto& symbols = remote_gdb::remoteLoadedSymbols().addrToName;

    addressLineNoMap.clear();
    labelLineNoMapInternal.clear();
    labels.clear();

    for (size_t i = 0; i < count; ++i) {
        const auto address = instructions[i].address;
        const auto line = static_cast<uint64_t>(i + 1);
        addressLineNoMap[address] = line;

        auto symbol = symbols.find(address);
        if (symbol != symbols.end()) {
            lineAddressLabels[static_cast<int>(i)] = symbol->second;
            labelLineNoMapInternal[symbol->second] = static_cast<int>(line);
            labels.push_back(symbol->second);
        } else {
            lineAddressLabels[static_cast<int>(i)] = formatAddress(address);
        }

        std::ostringstream offset;
        offset << "+0x" << std::hex << (address - entry);
        lineOffsetLabels[static_cast<int>(i)] = offset.str();

        text << instructions[i].mnemonic;
        if (instructions[i].op_str[0] != '\0') {
            text << ' ' << instructions[i].op_str;
        }
        if ((i + 1) < count) {
            text << '\n';
        }
    }

    lastInstructionLineNo = static_cast<uint64_t>(count);
    showRemoteDisassemblyInEditor(text.str(), 0, lineOffsetLabels, lineAddressLabels);

    cs_free(instructions, count);
    cs_close(&handle);
}

#ifndef _WIN32
bool loadElf64(const std::vector<uint8_t>& file, uint64_t& entry) {
    if (file.size() < sizeof(Elf64_Ehdr)) {
        return false;
    }

    const auto* header = reinterpret_cast<const Elf64_Ehdr*>(file.data());
    if (header->e_phentsize != sizeof(Elf64_Phdr) ||
        !rangeInFile(header->e_phoff, static_cast<uint64_t>(header->e_phnum) * header->e_phentsize, file.size())) {
        return false;
    }

    const auto* phdrs = reinterpret_cast<const Elf64_Phdr*>(file.data() + header->e_phoff);
    for (uint16_t i = 0; i < header->e_phnum; ++i) {
        if (phdrs[i].p_type != PT_LOAD) {
            continue;
        }
        if (!mapSegment(file, phdrs[i].p_vaddr, phdrs[i].p_offset,
                        phdrs[i].p_filesz, phdrs[i].p_memsz, phdrs[i].p_flags)) {
            return false;
        }
    }

    entry = header->e_entry;
    return entry != 0;
}

bool loadElf32(const std::vector<uint8_t>& file, uint64_t& entry) {
    if (file.size() < sizeof(Elf32_Ehdr)) {
        return false;
    }

    const auto* header = reinterpret_cast<const Elf32_Ehdr*>(file.data());
    if (header->e_phentsize != sizeof(Elf32_Phdr) ||
        !rangeInFile(header->e_phoff, static_cast<uint64_t>(header->e_phnum) * header->e_phentsize, file.size())) {
        return false;
    }

    const auto* phdrs = reinterpret_cast<const Elf32_Phdr*>(file.data() + header->e_phoff);
    for (uint16_t i = 0; i < header->e_phnum; ++i) {
        if (phdrs[i].p_type != PT_LOAD) {
            continue;
        }
        if (!mapSegment(file, phdrs[i].p_vaddr, phdrs[i].p_offset,
                        phdrs[i].p_filesz, phdrs[i].p_memsz, phdrs[i].p_flags)) {
            return false;
        }
    }

    entry = header->e_entry;
    return entry != 0;
}
#endif

}

bool loadElfBinaryForDebug(const std::string& path) {
    if (path.empty()) {
        return false;
    }
    if (remote_gdb::useRemoteDebugging()) {
        consoleWriteThreadSafe("elf >> local ELF loading is available in emulation mode only\n");
        return false;
    }

#ifdef _WIN32
    consoleWriteThreadSafe("elf >> ELF loading is not available on this platform yet\n");
    return false;
#else
    std::vector<uint8_t> file;
    if (!readWholeFile(path, file) || file.size() < EI_NIDENT ||
        std::memcmp(file.data(), ELFMAG, SELFMAG) != 0) {
        consoleWriteThreadSafe("elf >> not an ELF file: " + path + "\n");
        return false;
    }

    resetState(false);
    if (!createStack(icicle)) {
        return false;
    }

    uint64_t entry = 0;
    const auto elfClass = file[EI_CLASS];
    bool loaded = false;
    if (elfClass == ELFCLASS64) {
        loaded = loadElf64(file, entry);
    } else if (elfClass == ELFCLASS32) {
        loaded = loadElf32(file, entry);
    }

    if (!loaded) {
        consoleWriteThreadSafe("elf >> failed to map loadable segments from " + path + "\n");
        return false;
    }

    selectedFile = path;
    ENTRY_POINT_ADDRESS = entry;
    MEMORY_EDITOR_BASE = pageFloor(entry);
    icicle_set_pc(icicle, entry);

    remote_gdb::remoteLoadSymbolFile(path);
    buildEntryDisassemblyView(entry);

    icicle_add_execution_hook(icicle, instructionHook, nullptr);
    icicle_add_mem_write_hook(icicle, stackWriteHook, nullptr, STACK_ADDRESS, STACK_ADDRESS + STACK_SIZE);
    icicle_add_syscall_hook(icicle, handleSyscalls, icicle);
    installDebugWatchpointHooks();

    {
        std::lock_guard<std::mutex> lk(debugReadyMutex);
        isDebugReady = true;
    }
    debugReadyCv.notify_all();

    debugModeEnabled = true;
    codeHasRun = true;
    updateStack = true;
    updateRegs();
    consoleWriteThreadSafe("elf >> loaded " + path + " at entry " + formatAddress(entry) + "\n");
    return true;
#endif
}
