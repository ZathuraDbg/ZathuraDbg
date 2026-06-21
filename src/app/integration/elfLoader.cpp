#include "elfLoader.hpp"

#include "debugState.hpp"
#include "gdb/gdbRemote.hpp"
#include "interpreter/interpreter.hpp"
#include "linuxProcess.hpp"

#include "../app.hpp"

#ifndef _WIN32
#include <elf.h>
#endif

// <elf.h> is Linux-only, so on Windows (MinGW) the ELF program-header flag
// macros aren't defined. They leak into host-agnostic code — segmentProtection()
// below uses them outside the _WIN32 guards — so provide the spec-fixed values.
// Guarded with #ifndef so they never clash with the real <elf.h>. (Actual ELF
// loading is still gated off on Windows; see the _WIN32 blocks further down.)
#ifndef PF_X
#define PF_X 0x1
#endif
#ifndef PF_W
#define PF_W 0x2
#endif
#ifndef PF_R
#define PF_R 0x4
#endif

#include <algorithm>
#include <capstone/capstone.h>
#include <cstring>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <vector>

extern void instructionHook(void* userData, uint64_t address);
extern void stackWriteHook(void* data, uint64_t address, uint8_t size, uint64_t valueWritten);
extern int handleSyscalls(void* data, uint64_t syscall_nr, const SyscallArgs* args);

namespace {

constexpr uint64_t kPageSize = 0x1000;
constexpr uint64_t kDefaultPieBase = 0x555555554000ULL;
constexpr uint64_t kInterpreterBase = 0x7ffff7dd0000ULL;
constexpr size_t kLocalDisassemblyInstructionCount = 96;

std::string loadedElfPath;
std::map<uint64_t, std::string> gLocalElfSymbols;

struct ElfLoadResult {
    uint64_t initialPc = 0;
    uint64_t programEntry = 0;
    uint64_t loadBias = 0;
    uint64_t programHeaders = 0;
    uint64_t programHeaderEntrySize = 0;
    uint64_t programHeaderCount = 0;
    uint64_t minAddress = std::numeric_limits<uint64_t>::max();
    uint64_t maxAddress = 0;
    uint64_t brkStart = 0;
    uint64_t interpreterBase = 0;
    std::string interpreterPath;
};

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

bool hasElfMagic(const std::vector<uint8_t>& file) {
#ifndef _WIN32
    return file.size() >= EI_NIDENT && std::memcmp(file.data(), ELFMAG, SELFMAG) == 0;
#else
    (void)file;
    return false;
#endif
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

    std::vector<uint8_t> zeroPage(static_cast<size_t>(kPageSize), 0);
    for (uint64_t page = mapStart; page < mapStart + mapSize; page += kPageSize) {
        icicle_mem_write(icicle, page, zeroPage.data(), zeroPage.size());
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

void mergeLocalElfSymbols(const std::string& path, const uint64_t loadBias) {
    const auto symbols = remote_gdb::loadElfSymbols(path);
    for (const auto& [address, name] : symbols.addrToName) {
        if (!name.empty()) {
            gLocalElfSymbols[loadBias + address] = name;
        }
    }
}

void rebuildLocalElfSymbols(const ElfLoadResult& image) {
    gLocalElfSymbols.clear();
    mergeLocalElfSymbols(loadedElfPath, image.loadBias);
    if (!image.interpreterPath.empty()) {
        mergeLocalElfSymbols(image.interpreterPath, image.interpreterBase);
    }
}

std::string generatedLabelForAddress(const uint64_t address) {
    std::ostringstream out;
    out << "loc_" << std::hex << address;
    return out.str();
}

std::string exactLabelForAddress(const uint64_t address) {
    const auto symbol = gLocalElfSymbols.find(address);
    if (symbol != gLocalElfSymbols.end()) {
        return symbol->second;
    }
    return generatedLabelForAddress(address);
}

std::string lineAddressLabelForAddress(const uint64_t address) {
    const auto symbol = gLocalElfSymbols.find(address);
    if (symbol != gLocalElfSymbols.end()) {
        return symbol->second;
    }

    const auto nextSymbol = gLocalElfSymbols.upper_bound(address);
    if (nextSymbol != gLocalElfSymbols.begin()) {
        const auto previousSymbol = std::prev(nextSymbol);
        const auto offset = address - previousSymbol->first;
        if (offset > 0 && offset < 0x1000) {
            std::ostringstream out;
            out << previousSymbol->second << "+0x" << std::hex << offset;
            return out.str();
        }
    }

    return formatAddress(address);
}

std::optional<uint64_t> extractBranchTarget(const cs_insn& instruction) {
    if (instruction.detail == nullptr) {
        return std::nullopt;
    }

    for (uint8_t groupIndex = 0; groupIndex < instruction.detail->groups_count; ++groupIndex) {
        const auto group = instruction.detail->groups[groupIndex];
        if (group != CS_GRP_JUMP && group != CS_GRP_CALL) {
            continue;
        }

        const auto* detail = instruction.detail;
        switch (codeInformation.archIC) {
            case IC_ARCH_X86_64:
                for (uint8_t operandIndex = 0; operandIndex < detail->x86.op_count; ++operandIndex) {
                    if (detail->x86.operands[operandIndex].type == X86_OP_IMM) {
                        return static_cast<uint64_t>(detail->x86.operands[operandIndex].imm);
                    }
                }
                break;
            case IC_ARCH_AARCH64:
                for (uint8_t operandIndex = 0; operandIndex < detail->arm64.op_count; ++operandIndex) {
                    if (detail->arm64.operands[operandIndex].type == ARM64_OP_IMM) {
                        return static_cast<uint64_t>(detail->arm64.operands[operandIndex].imm);
                    }
                }
                break;
            case IC_ARCH_ARM:
            case IC_ARCH_THUMBV7M:
                for (uint8_t operandIndex = 0; operandIndex < detail->arm.op_count; ++operandIndex) {
                    if (detail->arm.operands[operandIndex].type == ARM_OP_IMM) {
                        return static_cast<uint64_t>(detail->arm.operands[operandIndex].imm);
                    }
                }
                break;
            default:
                break;
        }
        break;
    }

    return std::nullopt;
}

std::string operandTextWithLabel(const cs_insn& instruction,
                                 const std::map<uint64_t, std::string>& labelsByAddress) {
    std::string operands = instruction.op_str;
    const auto target = extractBranchTarget(instruction);
    if (!target.has_value()) {
        return operands;
    }

    std::optional<std::string> label;
    if (const auto visibleLabel = labelsByAddress.find(*target); visibleLabel != labelsByAddress.end()) {
        label = visibleLabel->second;
    } else if (const auto symbol = gLocalElfSymbols.find(*target); symbol != gLocalElfSymbols.end()) {
        label = symbol->second;
    }

    if (!label.has_value()) {
        return operands;
    }

    const auto rawAddress = formatAddress(*target);
    const auto addressPos = operands.find(rawAddress);
    if (addressPos != std::string::npos) {
        operands.replace(addressPos, rawAddress.size(), *label);
        return operands;
    }

    return *label;
}

void rebuildLocalBreakpointHighlights() {
    breakpointLines.clear();
    editor->HighlightBreakpoints(-1, true);

    for (const auto address : breakpointAddresses) {
        const auto it = addressLineNoMap.find(address);
        if (it == addressLineNoMap.end() || it->second == 0) {
            continue;
        }

        breakpointLines.push_back(it->second);
        editor->HighlightBreakpoints(static_cast<int>(it->second - 1));
    }
}

bool buildLocalDisassemblyView(const uint64_t startAddress, const uint64_t currentAddress) {
    const auto bytes = readEntryBytes(startAddress);
    if (!bytes.has_value() || bytes->empty()) {
        return false;
    }

    csh handle{};
    if (cs_open(codeInformation.archCS, codeInformation.modeCS, &handle) != CS_ERR_OK) {
        return false;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* instructions = nullptr;
    const auto count = cs_disasm(handle, bytes->data(), bytes->size(), startAddress,
                                 kLocalDisassemblyInstructionCount, &instructions);
    if (count == 0 || instructions == nullptr) {
        cs_close(&handle);
        return false;
    }

    std::unordered_set<uint64_t> visibleInstructionAddresses;
    for (size_t i = 0; i < count; ++i) {
        visibleInstructionAddresses.insert(instructions[i].address);
    }

    std::set<uint64_t> labelTargets;
    for (size_t i = 0; i < count; ++i) {
        const auto address = instructions[i].address;
        if (gLocalElfSymbols.contains(address) || address == startAddress || address == currentAddress) {
            labelTargets.insert(address);
        }
        if (auto target = extractBranchTarget(instructions[i]); target.has_value() &&
            visibleInstructionAddresses.contains(*target)) {
            labelTargets.insert(*target);
        }
    }

    std::map<uint64_t, std::string> labelsByAddress;
    std::unordered_set<std::string> usedLabelNames;
    for (const auto address : labelTargets) {
        if (!visibleInstructionAddresses.contains(address)) {
            continue;
        }

        std::string label = exactLabelForAddress(address);
        if (usedLabelNames.contains(label)) {
            label += "_" + generatedLabelForAddress(address);
        }
        usedLabelNames.insert(label);
        labelsByAddress[address] = label;
    }

    std::ostringstream text;
    std::map<int, std::string> lineAddressLabels;
    std::map<int, std::string> lineOffsetLabels;
    std::unordered_map<uint64_t, uint64_t> nextAddressLineNoMap;
    std::map<std::string, int> nextLabelLineNoMap;
    std::vector<std::string> nextLabels;
    std::vector<uint64_t> nextEmptyLineNumbers;
    int currentLine = -1;
    uint64_t displayLine = 1;
    bool firstLine = true;

    auto appendLine = [&](const std::string& line) {
        if (!firstLine) {
            text << '\n';
        }
        text << line;
        firstLine = false;
    };

    for (size_t i = 0; i < count; ++i) {
        const auto address = instructions[i].address;
        if (const auto label = labelsByAddress.find(address); label != labelsByAddress.end()) {
            if (!firstLine) {
                appendLine("");
                nextEmptyLineNumbers.push_back(displayLine);
                ++displayLine;
            }
            const auto lineIndex = static_cast<int>(displayLine - 1);
            appendLine(label->second + ":");
            lineAddressLabels[lineIndex] = formatAddress(address);
            nextLabelLineNoMap[label->second] = static_cast<int>(displayLine);
            nextLabels.push_back(label->second);
            ++displayLine;
        }

        const auto line = displayLine;
        const auto lineIndex = static_cast<int>(line - 1);
        nextAddressLineNoMap[address] = line;
        if (address == currentAddress) {
            currentLine = lineIndex;
        }

        lineAddressLabels[lineIndex] = lineAddressLabelForAddress(address);

        std::ostringstream offset;
        offset << "+0x" << std::hex << (address - startAddress);
        lineOffsetLabels[lineIndex] = offset.str();

        std::string lineText = instructions[i].mnemonic;
        const auto operands = operandTextWithLabel(instructions[i], labelsByAddress);
        if (!operands.empty()) {
            lineText += ' ';
            lineText += operands;
        }
        appendLine(lineText);
        ++displayLine;
    }

    addressLineNoMap = std::move(nextAddressLineNoMap);
    labelLineNoMapInternal = std::move(nextLabelLineNoMap);
    labels = std::move(nextLabels);
    emptyLineNumbers = std::move(nextEmptyLineNumbers);
    lastInstructionLineNo = displayLine > 1 ? displayLine - 1 : 0;
    showRemoteDisassemblyInEditor(text.str(), currentLine >= 0 ? currentLine : 0,
                                  lineOffsetLabels, lineAddressLabels);
    rebuildLocalBreakpointHighlights();

    cs_free(instructions, count);
    cs_close(&handle);

    if (currentLine >= 0) {
        safeHighlightLine(currentLine);
    }
    return currentLine >= 0;
}

#ifndef _WIN32
std::optional<std::string> readInterpreterPath(const std::vector<uint8_t>& file,
                                               const uint64_t offset,
                                               const uint64_t size) {
    if (size == 0 || !rangeInFile(offset, size, file.size())) {
        return std::nullopt;
    }

    std::string path(reinterpret_cast<const char*>(file.data() + offset), static_cast<size_t>(size));
    if (!path.empty() && path.back() == '\0') {
        path.pop_back();
    }
    return path.empty() ? std::nullopt : std::optional<std::string>(path);
}

std::optional<uint64_t> programHeadersAddress(const std::vector<uint8_t>& file,
                                              const Elf64_Ehdr* header,
                                              const Elf64_Phdr* phdrs,
                                              const uint64_t loadBias) {
    for (uint16_t i = 0; i < header->e_phnum; ++i) {
        if (phdrs[i].p_type == PT_PHDR) {
            return loadBias + phdrs[i].p_vaddr;
        }
    }

    for (uint16_t i = 0; i < header->e_phnum; ++i) {
        if (phdrs[i].p_type != PT_LOAD) {
            continue;
        }
        if (header->e_phoff >= phdrs[i].p_offset &&
            header->e_phoff < phdrs[i].p_offset + phdrs[i].p_filesz) {
            return loadBias + phdrs[i].p_vaddr + (header->e_phoff - phdrs[i].p_offset);
        }
    }

    if (rangeInFile(header->e_phoff, static_cast<uint64_t>(header->e_phnum) * header->e_phentsize, file.size())) {
        return loadBias + header->e_phoff;
    }
    return std::nullopt;
}

std::optional<ElfLoadResult> loadElf64Image(const std::vector<uint8_t>& file,
                                            const std::string& path,
                                            const std::optional<uint64_t> requestedBase) {
    if (file.size() < sizeof(Elf64_Ehdr)) {
        return std::nullopt;
    }

    const auto* header = reinterpret_cast<const Elf64_Ehdr*>(file.data());
    if (header->e_ident[EI_DATA] != ELFDATA2LSB ||
        header->e_ident[EI_VERSION] != EV_CURRENT ||
        header->e_machine != EM_X86_64 ||
        (header->e_type != ET_EXEC && header->e_type != ET_DYN) ||
        header->e_phentsize != sizeof(Elf64_Phdr) ||
        !rangeInFile(header->e_phoff, static_cast<uint64_t>(header->e_phnum) * header->e_phentsize, file.size())) {
        consoleWriteThreadSafe("elf >> unsupported ELF64 image: " + path + "\n");
        return std::nullopt;
    }

    const auto* phdrs = reinterpret_cast<const Elf64_Phdr*>(file.data() + header->e_phoff);
    uint64_t minVaddr = std::numeric_limits<uint64_t>::max();
    uint64_t maxVaddr = 0;
    for (uint16_t i = 0; i < header->e_phnum; ++i) {
        if (phdrs[i].p_type != PT_LOAD) {
            continue;
        }
        minVaddr = std::min(minVaddr, pageFloor(phdrs[i].p_vaddr));
        maxVaddr = std::max(maxVaddr, pageCeil(phdrs[i].p_vaddr + phdrs[i].p_memsz));
    }

    if (minVaddr == std::numeric_limits<uint64_t>::max()) {
        consoleWriteThreadSafe("elf >> ELF has no loadable segments: " + path + "\n");
        return std::nullopt;
    }

    const uint64_t loadBias = header->e_type == ET_DYN
        ? pageFloor(requestedBase.value_or(kDefaultPieBase)) - minVaddr
        : 0;

    ElfLoadResult result;
    result.loadBias = loadBias;
    result.initialPc = loadBias + header->e_entry;
    result.programEntry = result.initialPc;
    result.programHeaderEntrySize = header->e_phentsize;
    result.programHeaderCount = header->e_phnum;
    result.minAddress = loadBias + minVaddr;
    result.maxAddress = loadBias + maxVaddr;
    result.brkStart = pageCeil(result.maxAddress);

    for (uint16_t i = 0; i < header->e_phnum; ++i) {
        if (phdrs[i].p_type == PT_INTERP) {
            if (auto interpreter = readInterpreterPath(file, phdrs[i].p_offset, phdrs[i].p_filesz)) {
                result.interpreterPath = *interpreter;
            }
            continue;
        }

        if (phdrs[i].p_type != PT_LOAD) {
            continue;
        }
        if (!mapSegment(file, loadBias + phdrs[i].p_vaddr, phdrs[i].p_offset,
                        phdrs[i].p_filesz, phdrs[i].p_memsz, phdrs[i].p_flags)) {
            consoleWriteThreadSafe("elf >> failed to map segment from " + path + "\n");
            return std::nullopt;
        }
    }

    if (auto phdrAddress = programHeadersAddress(file, header, phdrs, loadBias)) {
        result.programHeaders = *phdrAddress;
    } else {
        consoleWriteThreadSafe("elf >> failed to resolve program header address for " + path + "\n");
        return std::nullopt;
    }

    return result.initialPc != 0 ? std::optional<ElfLoadResult>(result) : std::nullopt;
}

bool setX86_64ModeForElf() {
    codeInformation.archIC = IC_ARCH_X86_64;
    codeInformation.archKS = KS_ARCH_X86;
    codeInformation.archCS = CS_ARCH_X86;
    codeInformation.mode = UC_MODE_64;
    codeInformation.modeKS = KS_MODE_64;
    codeInformation.modeCS = CS_MODE_64;
    codeInformation.syntax = KS_OPT_SYNTAX_NASM;
    codeInformation.archStr = "x86_64";
    return initArch();
}

std::optional<ElfLoadResult> loadLinuxElfImage(const std::vector<uint8_t>& mainFile,
                                               const std::string& path) {
    auto mainImage = loadElf64Image(mainFile, path, std::nullopt);
    if (!mainImage.has_value()) {
        return std::nullopt;
    }

    ElfLoadResult result = *mainImage;
    if (!mainImage->interpreterPath.empty()) {
        std::vector<uint8_t> interpreterFile;
        if (!readWholeFile(mainImage->interpreterPath, interpreterFile) || !hasElfMagic(interpreterFile)) {
            consoleWriteThreadSafe("elf >> failed to read ELF interpreter " + mainImage->interpreterPath + "\n");
            return std::nullopt;
        }

        auto interpreter = loadElf64Image(interpreterFile, mainImage->interpreterPath, kInterpreterBase);
        if (!interpreter.has_value()) {
            return std::nullopt;
        }

        result.initialPc = interpreter->initialPc;
        result.interpreterPath = mainImage->interpreterPath;
        result.interpreterBase = interpreter->loadBias;
        result.brkStart = mainImage->brkStart;
    }

    return result;
}
#endif

}

bool isElfBinaryFile(const std::string& path) {
    std::vector<uint8_t> file;
    return readWholeFile(path, file) && hasElfMagic(file);
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
    if (!readWholeFile(path, file) || !hasElfMagic(file)) {
        consoleWriteThreadSafe("elf >> not an ELF file: " + path + "\n");
        return false;
    }

    if (!setX86_64ModeForElf()) {
        consoleWriteThreadSafe("elf >> failed to initialize x86_64 mode\n");
        return false;
    }

    clearLinuxProcess();
    loadedElfPath.clear();
    resetState(false);
    if (icicle == nullptr) {
        icicle = initIC();
    }
    if (icicle == nullptr) {
        consoleWriteThreadSafe("elf >> failed to initialize emulator\n");
        return false;
    }
    initRegistersToDefinedVals();

    const auto elfClass = file[EI_CLASS];
    std::optional<ElfLoadResult> loadedImage;
    if (elfClass == ELFCLASS64) {
        loadedImage = loadLinuxElfImage(file, path);
    } else if (elfClass == ELFCLASS32) {
        consoleWriteThreadSafe("elf >> ELF32 Linux execution is not supported yet; use an x86_64 ELF\n");
    }

    if (!loadedImage.has_value()) {
        consoleWriteThreadSafe("elf >> failed to map loadable segments from " + path + "\n");
        return false;
    }

    selectedFile = path;
    loadedElfPath = path;
    ENTRY_POINT_ADDRESS = loadedImage->initialPc;
    MEMORY_EDITOR_BASE = pageFloor(loadedImage->programEntry);
    codeExecutableEndAddress = 0;
    icicle_set_pc(icicle, loadedImage->initialPc);

    LinuxProcessImage processImage;
    processImage.path = path;
    processImage.interpreterPath = loadedImage->interpreterPath;
    processImage.initialPc = loadedImage->initialPc;
    processImage.programEntry = loadedImage->programEntry;
    processImage.programHeaders = loadedImage->programHeaders;
    processImage.programHeaderEntrySize = loadedImage->programHeaderEntrySize;
    processImage.programHeaderCount = loadedImage->programHeaderCount;
    processImage.interpreterBase = loadedImage->interpreterBase;
    processImage.loadBias = loadedImage->loadBias;
    processImage.brkStart = loadedImage->brkStart;
    configureLinuxProcess(processImage);
    if (!setupLinuxProcessStack(icicle)) {
        clearLinuxProcess();
        loadedElfPath.clear();
        return false;
    }

    remote_gdb::remoteLoadSymbolFile(path);
    rebuildLocalElfSymbols(*loadedImage);
    syncLocalElfDisassemblyView(loadedImage->initialPc, true);

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
    if (snapshot == nullptr) {
        snapshot = saveICSnapshot(icicle);
    }
    updateRegs();
    consoleWriteThreadSafe("elf >> loaded " + path + " at entry " + formatAddress(loadedImage->programEntry) + "\n");
    if (!loadedImage->interpreterPath.empty()) {
        consoleWriteThreadSafe("elf >> using interpreter " + loadedImage->interpreterPath +
                               " at " + formatAddress(loadedImage->initialPc) + "\n");
    }
    return true;
#endif
}

bool reloadElfBinaryForDebug() {
    const auto path = loadedElfPath;
    return !path.empty() && loadElfBinaryForDebug(path);
}

bool localElfBinaryLoaded() {
    return !loadedElfPath.empty();
}

bool syncLocalElfDisassemblyView(const uint64_t currentPc, const bool force) {
    if (loadedElfPath.empty()) {
        return false;
    }

    const auto lineIt = addressLineNoMap.find(currentPc);
    if (!force && lineIt != addressLineNoMap.end() && lineIt->second > 0) {
        safeHighlightLine(static_cast<int>(lineIt->second - 1));
        return true;
    }

    return buildLocalDisassemblyView(currentPc, currentPc);
}

void clearLocalElfBinary() {
    loadedElfPath.clear();
    gLocalElfSymbols.clear();
    clearLinuxProcess();
}
