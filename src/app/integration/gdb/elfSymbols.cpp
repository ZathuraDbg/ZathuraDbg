#include "elfSymbols.hpp"

#ifdef _WIN32

namespace remote_gdb {

ElfSymbols loadElfSymbols(const std::string&) {
    return {};
}

std::optional<SourceLocation> findSourceLocationForAddress(const ElfSymbols&, uint64_t) {
    return std::nullopt;
}

}

#else

#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <optional>
#include <string_view>
#include <vector>

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

std::string sectionStringAt(const std::string_view section, const uint64_t offset) {
    if (offset >= section.size()) {
        return {};
    }

    const char* start = section.data() + offset;
    const void* terminator = std::memchr(start, '\0', section.size() - static_cast<size_t>(offset));
    if (terminator == nullptr) {
        return {};
    }

    return {start, static_cast<const char*>(terminator)};
}

class DwarfReader {
public:
    DwarfReader(const void* data, const size_t size)
        : cursor_(static_cast<const uint8_t*>(data)),
          end_(static_cast<const uint8_t*>(data) + size) {}

    [[nodiscard]] size_t remaining() const {
        return static_cast<size_t>(end_ - cursor_);
    }

    [[nodiscard]] const uint8_t* position() const {
        return cursor_;
    }

    bool setPosition(const uint8_t* position) {
        if (position < cursor_ || position > end_) {
            return false;
        }
        cursor_ = position;
        return true;
    }

    bool skip(const size_t size) {
        if (size > remaining()) {
            return false;
        }
        cursor_ += size;
        return true;
    }

    bool readU8(uint8_t& value) {
        if (remaining() < 1) return false;
        value = *cursor_++;
        return true;
    }

    bool readS8(int8_t& value) {
        uint8_t raw = 0;
        if (!readU8(raw)) return false;
        value = static_cast<int8_t>(raw);
        return true;
    }

    bool readU16(uint16_t& value) {
        if (remaining() < sizeof(value)) return false;
        std::memcpy(&value, cursor_, sizeof(value));
        cursor_ += sizeof(value);
        return true;
    }

    bool readU32(uint32_t& value) {
        if (remaining() < sizeof(value)) return false;
        std::memcpy(&value, cursor_, sizeof(value));
        cursor_ += sizeof(value);
        return true;
    }

    bool readU64(uint64_t& value) {
        if (remaining() < sizeof(value)) return false;
        std::memcpy(&value, cursor_, sizeof(value));
        cursor_ += sizeof(value);
        return true;
    }

    bool readOffset(const uint8_t offsetSize, uint64_t& value) {
        if (offsetSize == 4) {
            uint32_t raw = 0;
            if (!readU32(raw)) return false;
            value = raw;
            return true;
        }
        if (offsetSize == 8) {
            return readU64(value);
        }
        return false;
    }

    bool readAddress(const uint8_t addressSize, uint64_t& value) {
        if (addressSize == 0 || addressSize > sizeof(value) || remaining() < addressSize) {
            return false;
        }
        value = 0;
        for (uint8_t i = 0; i < addressSize; ++i) {
            value |= static_cast<uint64_t>(cursor_[i]) << (i * 8);
        }
        cursor_ += addressSize;
        return true;
    }

    bool readULEB(uint64_t& value) {
        value = 0;
        unsigned int shift = 0;
        while (shift < 64) {
            uint8_t byte = 0;
            if (!readU8(byte)) return false;
            value |= static_cast<uint64_t>(byte & 0x7f) << shift;
            if ((byte & 0x80) == 0) return true;
            shift += 7;
        }
        return false;
    }

    bool readSLEB(int64_t& value) {
        value = 0;
        unsigned int shift = 0;
        uint8_t byte = 0;
        do {
            if (shift >= 64 || !readU8(byte)) return false;
            value |= static_cast<int64_t>(byte & 0x7f) << shift;
            shift += 7;
        } while ((byte & 0x80) != 0);

        if (shift < 64 && (byte & 0x40) != 0) {
            value |= -(int64_t{1} << shift);
        }
        return true;
    }

    bool readCString(std::string& value) {
        value.clear();
        const void* terminator = std::memchr(cursor_, '\0', remaining());
        if (terminator == nullptr) {
            return false;
        }
        const auto* end = static_cast<const uint8_t*>(terminator);
        value.assign(reinterpret_cast<const char*>(cursor_), reinterpret_cast<const char*>(end));
        cursor_ = end + 1;
        return true;
    }

private:
    const uint8_t* cursor_ = nullptr;
    const uint8_t* end_ = nullptr;
};

struct DwarfFormValue {
    std::string text;
    uint64_t unsignedValue = 0;
    bool hasUnsignedValue = false;
};

bool readDwarfFormValue(DwarfReader& reader,
                        const uint64_t form,
                        const uint8_t offsetSize,
                        const uint8_t addressSize,
                        const std::string_view debugLineStr,
                        const std::string_view debugStr,
                        DwarfFormValue& value) {
    value = {};

    constexpr uint64_t DW_FORM_addr = 0x01;
    constexpr uint64_t DW_FORM_block2 = 0x03;
    constexpr uint64_t DW_FORM_block4 = 0x04;
    constexpr uint64_t DW_FORM_data2 = 0x05;
    constexpr uint64_t DW_FORM_data4 = 0x06;
    constexpr uint64_t DW_FORM_data8 = 0x07;
    constexpr uint64_t DW_FORM_string = 0x08;
    constexpr uint64_t DW_FORM_block = 0x09;
    constexpr uint64_t DW_FORM_block1 = 0x0a;
    constexpr uint64_t DW_FORM_data1 = 0x0b;
    constexpr uint64_t DW_FORM_flag = 0x0c;
    constexpr uint64_t DW_FORM_sdata = 0x0d;
    constexpr uint64_t DW_FORM_strp = 0x0e;
    constexpr uint64_t DW_FORM_udata = 0x0f;
    constexpr uint64_t DW_FORM_sec_offset = 0x17;
    constexpr uint64_t DW_FORM_exprloc = 0x18;
    constexpr uint64_t DW_FORM_flag_present = 0x19;
    constexpr uint64_t DW_FORM_strx = 0x1a;
    constexpr uint64_t DW_FORM_addrx = 0x1b;
    constexpr uint64_t DW_FORM_data16 = 0x1e;
    constexpr uint64_t DW_FORM_line_strp = 0x1f;
    constexpr uint64_t DW_FORM_ref_sig8 = 0x20;
    constexpr uint64_t DW_FORM_strx1 = 0x25;
    constexpr uint64_t DW_FORM_strx2 = 0x26;
    constexpr uint64_t DW_FORM_strx3 = 0x27;
    constexpr uint64_t DW_FORM_strx4 = 0x28;

    uint64_t raw = 0;
    uint16_t raw16 = 0;
    uint32_t raw32 = 0;
    int64_t signedRaw = 0;
    uint8_t raw8 = 0;

    switch (form) {
        case DW_FORM_addr:
            if (!reader.readAddress(addressSize, raw)) return false;
            value.unsignedValue = raw;
            value.hasUnsignedValue = true;
            return true;
        case DW_FORM_data1:
        case DW_FORM_flag:
            if (!reader.readU8(raw8)) return false;
            value.unsignedValue = raw8;
            value.hasUnsignedValue = true;
            return true;
        case DW_FORM_data2:
            if (!reader.readU16(raw16)) return false;
            value.unsignedValue = raw16;
            value.hasUnsignedValue = true;
            return true;
        case DW_FORM_data4:
            if (!reader.readU32(raw32)) return false;
            value.unsignedValue = raw32;
            value.hasUnsignedValue = true;
            return true;
        case DW_FORM_data8:
        case DW_FORM_ref_sig8:
            if (!reader.readU64(raw)) return false;
            value.unsignedValue = raw;
            value.hasUnsignedValue = true;
            return true;
        case DW_FORM_udata:
        case DW_FORM_strx:
        case DW_FORM_addrx:
            if (!reader.readULEB(raw)) return false;
            value.unsignedValue = raw;
            value.hasUnsignedValue = true;
            return true;
        case DW_FORM_sdata:
            if (!reader.readSLEB(signedRaw)) return false;
            value.unsignedValue = static_cast<uint64_t>(signedRaw);
            value.hasUnsignedValue = true;
            return true;
        case DW_FORM_string:
            return reader.readCString(value.text);
        case DW_FORM_strp:
            if (!reader.readOffset(offsetSize, raw)) return false;
            value.text = sectionStringAt(debugStr, raw);
            value.unsignedValue = raw;
            value.hasUnsignedValue = true;
            return true;
        case DW_FORM_line_strp:
            if (!reader.readOffset(offsetSize, raw)) return false;
            value.text = sectionStringAt(debugLineStr, raw);
            value.unsignedValue = raw;
            value.hasUnsignedValue = true;
            return true;
        case DW_FORM_sec_offset:
            if (!reader.readOffset(offsetSize, raw)) return false;
            value.unsignedValue = raw;
            value.hasUnsignedValue = true;
            return true;
        case DW_FORM_block1:
            if (!reader.readU8(raw8)) return false;
            return reader.skip(raw8);
        case DW_FORM_block2:
            if (!reader.readU16(raw16)) return false;
            return reader.skip(raw16);
        case DW_FORM_block4:
            if (!reader.readU32(raw32)) return false;
            return reader.skip(raw32);
        case DW_FORM_block:
        case DW_FORM_exprloc:
            if (!reader.readULEB(raw)) return false;
            return reader.skip(static_cast<size_t>(raw));
        case DW_FORM_flag_present:
            value.unsignedValue = 1;
            value.hasUnsignedValue = true;
            return true;
        case DW_FORM_data16:
            return reader.skip(16);
        case DW_FORM_strx1:
            if (!reader.readU8(raw8)) return false;
            value.unsignedValue = raw8;
            value.hasUnsignedValue = true;
            return true;
        case DW_FORM_strx2:
            if (!reader.readU16(raw16)) return false;
            value.unsignedValue = raw16;
            value.hasUnsignedValue = true;
            return true;
        case DW_FORM_strx3:
            if (reader.remaining() < 3) return false;
            value.unsignedValue = 0;
            for (int i = 0; i < 3; ++i) {
                if (!reader.readU8(raw8)) return false;
                value.unsignedValue |= static_cast<uint64_t>(raw8) << (i * 8);
            }
            value.hasUnsignedValue = true;
            return true;
        case DW_FORM_strx4:
            if (!reader.readU32(raw32)) return false;
            value.unsignedValue = raw32;
            value.hasUnsignedValue = true;
            return true;
        default:
            return false;
    }
}

struct LineEntryFormat {
    uint64_t contentType = 0;
    uint64_t form = 0;
};

std::string combinePath(const std::string& directory, const std::string& filename) {
    if (filename.empty()) {
        return {};
    }

    std::filesystem::path filePath(filename);
    if (filePath.is_absolute() || directory.empty()) {
        return filePath.lexically_normal().string();
    }

    return (std::filesystem::path(directory) / filePath).lexically_normal().string();
}

std::string resolveSourcePath(const std::string& path, const std::filesystem::path& objectDirectory) {
    if (path.empty()) {
        return {};
    }

    auto existingAbsolutePath = [](const std::filesystem::path& candidate) -> std::string {
        std::error_code ec;
        if (std::filesystem::exists(candidate, ec) && std::filesystem::is_regular_file(candidate, ec)) {
            return std::filesystem::absolute(candidate, ec).lexically_normal().string();
        }
        return {};
    };

    const std::filesystem::path sourcePath(path);
    if (sourcePath.is_absolute()) {
        return sourcePath.lexically_normal().string();
    }

    if (auto resolved = existingAbsolutePath(sourcePath); !resolved.empty()) {
        return resolved;
    }

    if (!objectDirectory.empty()) {
        const auto objectRelative = objectDirectory / sourcePath;
        if (auto resolved = existingAbsolutePath(objectRelative); !resolved.empty()) {
            return resolved;
        }
    }

    std::vector<std::filesystem::path> sourceRoots;
    if (const char* rustSourcePath = std::getenv("RUST_SRC_PATH"); rustSourcePath != nullptr && rustSourcePath[0] != '\0') {
        sourceRoots.emplace_back(rustSourcePath);
    }
    sourceRoots.emplace_back("/usr/lib/rustlib/src/rust");
    sourceRoots.emplace_back("/usr/local/lib/rustlib/src/rust");

    if (const char* home = std::getenv("HOME"); home != nullptr && home[0] != '\0') {
        const auto rustupToolchains = std::filesystem::path(home) / ".rustup" / "toolchains";
        std::error_code ec;
        if (std::filesystem::is_directory(rustupToolchains, ec)) {
            for (const auto& entry : std::filesystem::directory_iterator(rustupToolchains, ec)) {
                if (ec) {
                    break;
                }
                if (entry.is_directory(ec)) {
                    sourceRoots.emplace_back(entry.path() / "lib" / "rustlib" / "src" / "rust");
                }
            }
        }
    }

    for (const auto& root : sourceRoots) {
        if (auto resolved = existingAbsolutePath(root / sourcePath); !resolved.empty()) {
            return resolved;
        }
    }

    return sourcePath.lexically_normal().string();
}

bool readLineEntryFormats(DwarfReader& reader, std::vector<LineEntryFormat>& formats) {
    uint8_t count = 0;
    if (!reader.readU8(count)) {
        return false;
    }

    formats.clear();
    formats.reserve(count);
    for (uint8_t i = 0; i < count; ++i) {
        LineEntryFormat format;
        if (!reader.readULEB(format.contentType) || !reader.readULEB(format.form)) {
            return false;
        }
        formats.push_back(format);
    }
    return true;
}

bool readV5LineEntries(DwarfReader& reader,
                       const std::vector<LineEntryFormat>& formats,
                       const bool files,
                       const std::vector<std::string>& directories,
                       const uint8_t offsetSize,
                       const uint8_t addressSize,
                       const std::string_view debugLineStr,
                       const std::string_view debugStr,
                       std::vector<std::string>& output) {
    constexpr uint64_t DW_LNCT_path = 0x01;
    constexpr uint64_t DW_LNCT_directory_index = 0x02;

    uint64_t entryCount = 0;
    if (!reader.readULEB(entryCount)) {
        return false;
    }

    output.clear();
    output.reserve(static_cast<size_t>(entryCount));

    for (uint64_t i = 0; i < entryCount; ++i) {
        std::string path;
        uint64_t directoryIndex = 0;
        for (const auto& format : formats) {
            DwarfFormValue value;
            if (!readDwarfFormValue(reader, format.form, offsetSize, addressSize,
                                    debugLineStr, debugStr, value)) {
                return false;
            }

            if (format.contentType == DW_LNCT_path) {
                path = std::move(value.text);
            } else if (format.contentType == DW_LNCT_directory_index && value.hasUnsignedValue) {
                directoryIndex = value.unsignedValue;
            }
        }

        if (files && !path.empty() && directoryIndex < directories.size()) {
            path = combinePath(directories[static_cast<size_t>(directoryIndex)], path);
        }
        output.push_back(path);
    }

    return true;
}

void parseDebugLineSection(ElfSymbols& result,
                           const std::string_view debugLine,
                           const std::string_view debugLineStr,
                           const std::string_view debugStr,
                           const uint8_t defaultAddressSize,
                           const std::filesystem::path& objectDirectory) {
    if (debugLine.empty()) {
        return;
    }

    DwarfReader reader(debugLine.data(), debugLine.size());
    while (reader.remaining() >= sizeof(uint32_t) + sizeof(uint16_t)) {
        uint32_t unitLength32 = 0;
        if (!reader.readU32(unitLength32)) {
            return;
        }

        uint64_t unitLength = unitLength32;
        uint8_t offsetSize = 4;
        if (unitLength32 == 0xffffffffU) {
            if (!reader.readU64(unitLength)) {
                return;
            }
            offsetSize = 8;
        }

        if (unitLength == 0 || unitLength > reader.remaining()) {
            return;
        }

        DwarfReader unit(reader.position(), static_cast<size_t>(unitLength));
        if (!reader.skip(static_cast<size_t>(unitLength))) {
            return;
        }

        uint16_t version = 0;
        if (!unit.readU16(version) || version < 2 || version > 5) {
            continue;
        }

        uint8_t addressSize = defaultAddressSize;
        if (version >= 5) {
            uint8_t segmentSelectorSize = 0;
            if (!unit.readU8(addressSize) || !unit.readU8(segmentSelectorSize)) {
                continue;
            }
        }

        uint64_t headerLength = 0;
        if (!unit.readOffset(offsetSize, headerLength) || headerLength > unit.remaining()) {
            continue;
        }
        const uint8_t* headerEnd = unit.position() + headerLength;

        uint8_t minimumInstructionLength = 0;
        uint8_t maximumOperationsPerInstruction = 1;
        uint8_t defaultIsStatement = 0;
        int8_t lineBase = 0;
        uint8_t lineRange = 0;
        uint8_t opcodeBase = 0;

        if (!unit.readU8(minimumInstructionLength)) continue;
        if (version >= 4 && !unit.readU8(maximumOperationsPerInstruction)) continue;
        if (!unit.readU8(defaultIsStatement) ||
            !unit.readS8(lineBase) ||
            !unit.readU8(lineRange) ||
            !unit.readU8(opcodeBase) ||
            opcodeBase == 0 ||
            lineRange == 0 ||
            minimumInstructionLength == 0) {
            continue;
        }
        if (maximumOperationsPerInstruction == 0) {
            maximumOperationsPerInstruction = 1;
        }

        std::vector<uint8_t> standardOpcodeLengths(opcodeBase, 0);
        bool opcodeLengthsOk = true;
        for (uint8_t opcode = 1; opcode < opcodeBase; ++opcode) {
            if (!unit.readU8(standardOpcodeLengths[opcode])) {
                opcodeLengthsOk = false;
                break;
            }
        }
        if (!opcodeLengthsOk) {
            continue;
        }

        std::vector<std::string> directories;
        std::vector<std::string> files;
        uint64_t initialFileIndex = 1;

        if (version >= 5) {
            initialFileIndex = 0;

            std::vector<LineEntryFormat> directoryFormats;
            if (!readLineEntryFormats(unit, directoryFormats) ||
                !readV5LineEntries(unit, directoryFormats, false, directories, offsetSize,
                                   addressSize, debugLineStr, debugStr, directories)) {
                continue;
            }

            std::vector<LineEntryFormat> fileFormats;
            if (!readLineEntryFormats(unit, fileFormats) ||
                !readV5LineEntries(unit, fileFormats, true, directories, offsetSize,
                                   addressSize, debugLineStr, debugStr, files)) {
                continue;
            }
        } else {
            directories.push_back("");
            while (unit.position() < headerEnd) {
                std::string directory;
                if (!unit.readCString(directory)) {
                    break;
                }
                if (directory.empty()) {
                    break;
                }
                directories.push_back(directory);
            }

            files.push_back("");
            while (unit.position() < headerEnd) {
                std::string filename;
                if (!unit.readCString(filename)) {
                    break;
                }
                if (filename.empty()) {
                    break;
                }
                uint64_t directoryIndex = 0;
                uint64_t ignored = 0;
                if (!unit.readULEB(directoryIndex) ||
                    !unit.readULEB(ignored) ||
                    !unit.readULEB(ignored)) {
                    break;
                }

                const std::string directory =
                    directoryIndex < directories.size() ? directories[static_cast<size_t>(directoryIndex)] : "";
                files.push_back(combinePath(directory, filename));
            }
        }

        if (!unit.setPosition(headerEnd)) {
            continue;
        }

        struct LineState {
            uint64_t address = 0;
            uint64_t opIndex = 0;
            uint64_t file = 1;
            int64_t line = 1;
            uint64_t column = 0;
            bool isStatement = false;
            bool basicBlock = false;
            bool prologueEnd = false;
            bool epilogueBegin = false;
            uint64_t isa = 0;
        };

        auto resetState = [&]() {
            return LineState{0, 0, initialFileIndex, 1, 0,
                             defaultIsStatement != 0, false, false, false, 0};
        };

        LineState state = resetState();

        auto advanceAddress = [&](const uint64_t operationAdvance) {
            state.address += minimumInstructionLength *
                ((state.opIndex + operationAdvance) / maximumOperationsPerInstruction);
            state.opIndex = (state.opIndex + operationAdvance) % maximumOperationsPerInstruction;
        };

        auto fileForIndex = [&](const uint64_t fileIndex) -> std::string {
            if (fileIndex < files.size() && !files[static_cast<size_t>(fileIndex)].empty()) {
                return files[static_cast<size_t>(fileIndex)];
            }
            if (fileIndex > 0 && fileIndex - 1 < files.size() &&
                !files[static_cast<size_t>(fileIndex - 1)].empty()) {
                return files[static_cast<size_t>(fileIndex - 1)];
            }
            return {};
        };

        auto appendRow = [&]() {
            if (state.address == 0 || state.line <= 0) {
                return;
            }

            auto file = fileForIndex(state.file);
            if (file.empty()) {
                return;
            }

            SourceLocation location;
            location.file = resolveSourcePath(file, objectDirectory);
            location.line = static_cast<uint64_t>(state.line);
            location.column = state.column;
            result.addrToSourceLine[state.address] = std::move(location);
        };

        while (unit.remaining() > 0) {
            uint8_t opcode = 0;
            if (!unit.readU8(opcode)) {
                break;
            }

            if (opcode >= opcodeBase) {
                const uint8_t adjustedOpcode = opcode - opcodeBase;
                const uint64_t operationAdvance = adjustedOpcode / lineRange;
                advanceAddress(operationAdvance);
                state.line += lineBase + (adjustedOpcode % lineRange);
                appendRow();
                state.basicBlock = false;
                state.prologueEnd = false;
                state.epilogueBegin = false;
                continue;
            }

            if (opcode == 0) {
                uint64_t instructionLength = 0;
                if (!unit.readULEB(instructionLength) || instructionLength > unit.remaining()) {
                    break;
                }
                DwarfReader extended(unit.position(), static_cast<size_t>(instructionLength));
                if (!unit.skip(static_cast<size_t>(instructionLength))) {
                    break;
                }

                uint8_t extendedOpcode = 0;
                if (!extended.readU8(extendedOpcode)) {
                    continue;
                }

                constexpr uint8_t DW_LNE_end_sequence = 1;
                constexpr uint8_t DW_LNE_set_address = 2;
                constexpr uint8_t DW_LNE_define_file = 3;
                constexpr uint8_t DW_LNE_set_discriminator = 4;

                if (extendedOpcode == DW_LNE_end_sequence) {
                    state = resetState();
                } else if (extendedOpcode == DW_LNE_set_address) {
                    uint64_t address = 0;
                    if (extended.readAddress(addressSize, address)) {
                        state.address = address;
                        state.opIndex = 0;
                    }
                } else if (extendedOpcode == DW_LNE_define_file && version < 5) {
                    std::string filename;
                    uint64_t directoryIndex = 0;
                    uint64_t ignored = 0;
                    if (extended.readCString(filename) &&
                        extended.readULEB(directoryIndex) &&
                        extended.readULEB(ignored) &&
                        extended.readULEB(ignored)) {
                        const std::string directory =
                            directoryIndex < directories.size()
                                ? directories[static_cast<size_t>(directoryIndex)]
                                : "";
                        files.push_back(combinePath(directory, filename));
                    }
                } else if (extendedOpcode == DW_LNE_set_discriminator) {
                    uint64_t ignored = 0;
                    extended.readULEB(ignored);
                }
                continue;
            }

            constexpr uint8_t DW_LNS_copy = 1;
            constexpr uint8_t DW_LNS_advance_pc = 2;
            constexpr uint8_t DW_LNS_advance_line = 3;
            constexpr uint8_t DW_LNS_set_file = 4;
            constexpr uint8_t DW_LNS_set_column = 5;
            constexpr uint8_t DW_LNS_negate_stmt = 6;
            constexpr uint8_t DW_LNS_set_basic_block = 7;
            constexpr uint8_t DW_LNS_const_add_pc = 8;
            constexpr uint8_t DW_LNS_fixed_advance_pc = 9;
            constexpr uint8_t DW_LNS_set_prologue_end = 10;
            constexpr uint8_t DW_LNS_set_epilogue_begin = 11;
            constexpr uint8_t DW_LNS_set_isa = 12;

            uint64_t unsignedValue = 0;
            int64_t signedValue = 0;
            uint16_t fixedAdvance = 0;

            switch (opcode) {
                case DW_LNS_copy:
                    appendRow();
                    state.basicBlock = false;
                    state.prologueEnd = false;
                    state.epilogueBegin = false;
                    break;
                case DW_LNS_advance_pc:
                    if (!unit.readULEB(unsignedValue)) goto doneUnit;
                    advanceAddress(unsignedValue);
                    break;
                case DW_LNS_advance_line:
                    if (!unit.readSLEB(signedValue)) goto doneUnit;
                    state.line += signedValue;
                    break;
                case DW_LNS_set_file:
                    if (!unit.readULEB(state.file)) goto doneUnit;
                    break;
                case DW_LNS_set_column:
                    if (!unit.readULEB(state.column)) goto doneUnit;
                    break;
                case DW_LNS_negate_stmt:
                    state.isStatement = !state.isStatement;
                    break;
                case DW_LNS_set_basic_block:
                    state.basicBlock = true;
                    break;
                case DW_LNS_const_add_pc:
                    advanceAddress((255 - opcodeBase) / lineRange);
                    break;
                case DW_LNS_fixed_advance_pc:
                    if (!unit.readU16(fixedAdvance)) goto doneUnit;
                    state.address += fixedAdvance;
                    state.opIndex = 0;
                    break;
                case DW_LNS_set_prologue_end:
                    state.prologueEnd = true;
                    break;
                case DW_LNS_set_epilogue_begin:
                    state.epilogueBegin = true;
                    break;
                case DW_LNS_set_isa:
                    if (!unit.readULEB(state.isa)) goto doneUnit;
                    break;
                default:
                    if (opcode < standardOpcodeLengths.size()) {
                        for (uint8_t i = 0; i < standardOpcodeLengths[opcode]; ++i) {
                            if (!unit.readULEB(unsignedValue)) goto doneUnit;
                        }
                    }
                    break;
            }
        }

doneUnit:
        continue;
    }
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
    const auto objectDirectory = std::filesystem::path(path).parent_path();

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
        if (ehdr->e_shentsize != sizeof(Elf64_Shdr) ||
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
        if (ehdr32->e_shentsize != sizeof(Elf32_Shdr) ||
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

    std::string_view debugLine;
    std::string_view debugLineStr;
    std::string_view debugStr;

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
        if (std::strcmp(secName, ".debug_line") == 0 && rangeInFile(secOff, secSize, fileSize)) {
            debugLine = std::string_view(reinterpret_cast<const char*>(data) + secOff, static_cast<size_t>(secSize));
            continue;
        }
        if (std::strcmp(secName, ".debug_line_str") == 0 && rangeInFile(secOff, secSize, fileSize)) {
            debugLineStr = std::string_view(reinterpret_cast<const char*>(data) + secOff, static_cast<size_t>(secSize));
            continue;
        }
        if (std::strcmp(secName, ".debug_str") == 0 && rangeInFile(secOff, secSize, fileSize)) {
            debugStr = std::string_view(reinterpret_cast<const char*>(data) + secOff, static_cast<size_t>(secSize));
            continue;
        }
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

    parseDebugLineSection(result, debugLine, debugLineStr, debugStr,
                          static_cast<uint8_t>(is64 ? 8 : 4), objectDirectory);

    munmap(data, fileSize);
    return result;
}

std::optional<SourceLocation> findSourceLocationForAddress(const ElfSymbols& symbols, const uint64_t address) {
    if (symbols.addrToSourceLine.empty()) {
        return std::nullopt;
    }

    auto it = symbols.addrToSourceLine.upper_bound(address);
    if (it == symbols.addrToSourceLine.begin()) {
        return std::nullopt;
    }

    --it;
    if (it->second.file.empty() || it->second.line == 0) {
        return std::nullopt;
    }
    return it->second;
}

}

#endif
