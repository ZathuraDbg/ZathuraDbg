#include "gdbRemote.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <set>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <map>
#include <mutex>
#include <optional>
#include <regex>
#include <sstream>
#include <span>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using socket_handle_t = SOCKET;
constexpr socket_handle_t invalid_socket_handle = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
using socket_handle_t = int;
constexpr socket_handle_t invalid_socket_handle = -1;
#endif

#include "../../arch/arch.hpp"
#include "../../../utils/stringHelper.hpp"

namespace remote_gdb {

namespace {

RemoteLogSink g_logSink;
RemoteArchHook g_archHook;
constexpr size_t kMaxPacketPayloadSize = 16 * 1024 * 1024;
constexpr size_t kMaxSkippedPacketBytes = 4096;
constexpr size_t kMaxChecksumFailures = 3;

void log(const std::string& text) {
    if (g_logSink) g_logSink(text);
}

struct RemoteRegisterDescriptor {
    std::string name;
    std::string type;
    std::string group;
    uint32_t regnum = 0;
    size_t bitsize = 0;
    size_t offset = 0;
};

struct DecodedInstruction {
    uint64_t address = 0;
    size_t size = 0;
    bool isCall = false;
    std::string mnemonic;
};

std::string formatHexByte(uint8_t byte) {
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

void closeSocket(socket_handle_t handle) {
    if (handle == invalid_socket_handle) {
        return;
    }
#ifdef _WIN32
    closesocket(handle);
#else
    close(handle);
#endif
}

bool sendAll(socket_handle_t handle, std::string_view bytes) {
    size_t written = 0;
    while (written < bytes.size()) {
#ifdef _WIN32
        const int sent = send(handle, bytes.data() + written,
                              static_cast<int>(bytes.size() - written), 0);
#else
        const auto sent = send(handle, bytes.data() + written, bytes.size() - written, 0);
#endif
        if (sent <= 0) {
            return false;
        }
        written += static_cast<size_t>(sent);
    }
    return true;
}

bool recvByte(socket_handle_t handle, char& byte) {
#ifdef _WIN32
    const int received = recv(handle, &byte, 1, 0);
#else
    const auto received = recv(handle, &byte, 1, 0);
#endif
    return received == 1;
}

void clearSocketTimeout(socket_handle_t handle) {
#ifdef _WIN32
    DWORD zero = 0;
    setsockopt(handle, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&zero), sizeof(zero));
    setsockopt(handle, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&zero), sizeof(zero));
#else
    struct timeval zero{0, 0};
    setsockopt(handle, SOL_SOCKET, SO_RCVTIMEO, &zero, sizeof(zero));
    setsockopt(handle, SOL_SOCKET, SO_SNDTIMEO, &zero, sizeof(zero));
#endif
}

std::optional<uint64_t> littleEndianUint(std::span<const uint8_t> bytes) {
    if (bytes.size() > sizeof(uint64_t)) {
        return std::nullopt;
    }
    uint64_t value = 0;
    for (size_t i = 0; i < bytes.size(); ++i) {
        value |= static_cast<uint64_t>(bytes[i]) << (i * 8);
    }
    return value;
}

std::vector<uint8_t> littleEndianBytes(uint64_t value, size_t size) {
    std::vector<uint8_t> bytes(size, 0);
    for (size_t i = 0; i < size; ++i) {
        bytes[i] = static_cast<uint8_t>((value >> (i * 8)) & 0xff);
    }
    return bytes;
}

static ElfSymbols globalElfSymbols;

class GdbRemoteClient {
public:
    bool connectTo(const RemoteConnectionConfig& config);
    void disconnect();

    [[nodiscard]] bool connected() const {
        return socket_ != invalid_socket_handle;
    }

    bool refreshState();
    bool resume(bool singleStep);
    bool stepOver();
    bool interrupt();
    bool restart();
    std::optional<RemoteDisassemblyView> buildDisassemblyView(
        size_t instructionCount, std::optional<uint64_t> startAddress);

    std::optional<std::vector<uint8_t>> registerBytes(const std::string& regName);
    bool writeRegister(const std::string& regName, const std::vector<uint8_t>& bytes);
    std::optional<std::vector<uint8_t>> readMemory(uint64_t address, size_t size);
    std::optional<std::vector<uint8_t>> readMemoryWithFallback(uint64_t address, size_t preferredSize);
    bool writeMemory(uint64_t address, const std::vector<uint8_t>& bytes);
    bool insertBreakpoint(uint64_t address);
    bool removeBreakpoint(uint64_t address);
    bool sendMonitorCommand(const std::string& command, std::string& response);
    bool sendRawPacket(const std::string& payload, std::string& response);

    [[nodiscard]] const std::vector<RemoteMemoryRegion>& memoryRegions() const {
        return memoryRegions_;
    }

    [[nodiscard]] bool supportsMemoryMap() const {
        return supportsMemoryMap_;
    }

    [[nodiscard]] bool supportsTargetXml() const {
        return supportsTargetXml_;
    }

    [[nodiscard]] std::string lastStopReason() const {
        return lastStopReason_;
    }

    std::optional<uint64_t> programCounter();
    std::optional<uint64_t> stackPointer();

    void clearCachedState() {
        registerBlob_.clear();
        lastStopReason_.clear();
        memoryRegions_.clear();
        cachedRegValues_.clear();
    }

private:
    bool sendPacket(const std::string& payload);
    bool transact(const std::string& payload, std::string& response);
    bool readPacket(std::string& payload);
    void resetSessionState();
    void teardownSocket();
    bool initialHandshake();
    bool loadTargetDescription();
    bool loadFeatureAnnex(const std::string& annex, std::string& xml);
    bool parseTargetDescriptionXml(const std::string& xml);
    bool loadMemoryMap();
    bool parseMemoryMapXml(const std::string& xml);
    bool refreshRegisters();
    bool ensureRegisterDescriptor(const std::string& regName);
    std::optional<std::vector<uint8_t>> readRegisterSlice(const std::string& regName);
    bool writeRegisterSlice(const std::string& regName, const std::vector<uint8_t>& bytes);
    bool queryStopReason();
    void parseStopRegisters(const std::string& response);
    std::optional<DecodedInstruction> decodeCurrentInstruction();
    static bool isCallInstruction(const cs_insn& instruction);
    [[nodiscard]] bool hasTrackedBreakpoint(uint64_t address) const;
    std::optional<std::vector<uint8_t>> readDisassemblyBytes(uint64_t startAddress, size_t preferredSize);
    std::optional<uint64_t> archRegisterValue(const char* name);
    static std::string attrValue(const std::string& tag, const char* name);
    static std::string trim(std::string value);

    socket_handle_t socket_ = invalid_socket_handle;
    bool noAckMode_ = false;
    bool supportsTargetXml_ = false;
    bool supportsMemoryMap_ = false;
    bool supportsVCont_ = false;

    std::unordered_map<std::string, std::string> supportedFeatures_;
    std::vector<RemoteRegisterDescriptor> registers_;
    std::unordered_map<std::string, size_t> registerIndexByName_;
    std::vector<uint8_t> registerBlob_;
    std::vector<RemoteMemoryRegion> memoryRegions_;
    std::unordered_set<uint64_t> activeBreakpoints_;
    std::string lastStopReason_;
    std::unordered_map<unsigned int, std::vector<uint8_t>> cachedRegValues_;
};

GdbRemoteClient client;
std::mutex clientMutex;

std::string archAliasFromTargetXml(const std::string& targetArch) {
    const auto lowered = toLowerCase(targetArch);
    if (lowered.contains("x86-64") || lowered.contains("i386:x86-64")) {
        return "x86_64";
    }
    if (lowered.contains("aarch64")) {
        return "aarch64";
    }
    if (lowered.contains("arm")) {
        return "arm";
    }
    return {};
}

void maybeApplyRemoteArchitecture(const std::string& targetArch) {
    const auto alias = archAliasFromTargetXml(targetArch);
    if (alias.empty()) return;
    if (g_archHook) g_archHook(alias);
}

std::vector<RemoteRegisterDescriptor> fallbackRegisterLayout() {
    std::vector<RemoteRegisterDescriptor> descriptors;
    std::vector<std::string> names;

    switch (codeInformation.archIC) {
        case IC_ARCH_X86_64:
            names = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                     "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                     "rip", "eflags", "cs", "ss", "ds", "es", "fs", "gs"};
            break;
        case IC_ARCH_AARCH64:
            for (int i = 0; i <= 30; ++i) {
                names.push_back("x" + std::to_string(i));
            }
            names.push_back("sp");
            names.push_back("pc");
            names.push_back("nzcv");
            break;
        case IC_ARCH_ARM:
        case IC_ARCH_THUMBV7M:
            for (int i = 0; i <= 12; ++i) {
                names.push_back("r" + std::to_string(i));
            }
            names.push_back("sp");
            names.push_back("lr");
            names.push_back("pc");
            names.push_back("cpsr");
            break;
        default:
            break;
    }

    size_t offset = 0;
    uint32_t regnum = 0;
    for (const auto& name : names) {
        if (!regInfoMap.contains(name)) {
            continue;
        }

        RemoteRegisterDescriptor desc;
        desc.name = name;
        desc.regnum = regnum++;
        desc.bitsize = regInfoMap[name];
        desc.offset = offset;
        offset += desc.bitsize / 8;
        descriptors.push_back(desc);
    }

    return descriptors;
}

#ifdef _WIN32
bool ensureWinsockInit() {
    static const bool initialized = []() {
        WSADATA wsaData;
        return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
    }();
    return initialized;
}
#endif

bool GdbRemoteClient::connectTo(const RemoteConnectionConfig& config) {
    disconnect();

#ifdef _WIN32
    if (!ensureWinsockInit()) {
        log("remote >> failed to initialize winsock\n");
        return false;
    }
#endif

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* result = nullptr;
    const auto port = std::to_string(config.port);
    if (getaddrinfo(config.host.c_str(), port.c_str(), &hints, &result) != 0) {
        log("remote >> failed to resolve host\n");
        return false;
    }

    for (auto* rp = result; rp != nullptr; rp = rp->ai_next) {
        socket_ = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (socket_ == invalid_socket_handle) {
            continue;
        }

        if (::connect(socket_, rp->ai_addr, static_cast<int>(rp->ai_addrlen)) == 0) {
            break;
        }

        closeSocket(socket_);
        socket_ = invalid_socket_handle;
    }

    freeaddrinfo(result);

    if (socket_ == invalid_socket_handle) {
        log("remote >> Failed to connect to the remote target. Are you sure it's running?\n");
        return false;
    }

#ifdef _WIN32
    DWORD timeout_ms = 5000;
    setsockopt(socket_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
    setsockopt(socket_, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
#else
    struct timeval tv{5, 0};
    setsockopt(socket_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(socket_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    log("remote >> connected to " + config.host + ":" + std::to_string(config.port) + "\n");
    if (!initialHandshake() || !refreshState()) {
        log("remote >> handshake/init failed, disconnecting\n");
        disconnect();
        return false;
    }
    clearSocketTimeout(socket_);
    return true;
}

void GdbRemoteClient::disconnect() {
    if (socket_ != invalid_socket_handle) {
        closeSocket(socket_);
        socket_ = invalid_socket_handle;
    }
    resetSessionState();
}

void GdbRemoteClient::resetSessionState() {
    noAckMode_ = false;
    supportsTargetXml_ = false;
    supportsMemoryMap_ = false;
    supportsVCont_ = false;
    supportedFeatures_.clear();
    registers_.clear();
    registerIndexByName_.clear();
    registerBlob_.clear();
    memoryRegions_.clear();
    activeBreakpoints_.clear();
    lastStopReason_.clear();
    cachedRegValues_.clear();
}

bool GdbRemoteClient::sendPacket(const std::string& payload) {
    if (!connected()) {
        return false;
    }

    std::string packet;
    packet.reserve(payload.size() + 4);
    packet.push_back('$');
    packet += payload;
    packet.push_back('#');
    packet += formatHexByte(packetChecksum(payload));

    if (!sendAll(socket_, packet)) {
        return false;
    }

    if (noAckMode_) {
        return true;
    }

    char ack = '\0';
    while (recvByte(socket_, ack)) {
        if (ack == '+') {
            return true;
        }
        if (ack == '-') {
            return sendAll(socket_, packet);
        }
        if (ack == '$') {
            return false;
        }
    }

    return false;
}

bool GdbRemoteClient::readPacket(std::string& payload) {
    payload.clear();
    if (!connected()) {
        return false;
    }

    size_t skippedBytes = 0;
    size_t checksumFailures = 0;
    while (skippedBytes < kMaxSkippedPacketBytes && checksumFailures < kMaxChecksumFailures) {
        char ch = '\0';
        if (!recvByte(socket_, ch)) {
            return false;
        }

        if (ch == '+' || ch == '-') {
            ++skippedBytes;
            continue;
        }

        if (ch != '$') {
            ++skippedBytes;
            if (static_cast<unsigned char>(ch) == 0x03) {
                continue;
            }
            continue;
        }

        std::string packet;
        while (true) {
            if (!recvByte(socket_, ch)) {
                return false;
            }
            if (ch == '#') {
                break;
            }
            packet.push_back(ch);
            if (packet.size() > kMaxPacketPayloadSize) {
                log("remote >> packet payload exceeded size limit\n");
                return false;
            }
        }

        std::array<char, 2> checksumChars{};
        if (!recvByte(socket_, checksumChars[0]) || !recvByte(socket_, checksumChars[1])) {
            return false;
        }

        unsigned int expected = 0;
        auto parse = std::from_chars(checksumChars.data(), checksumChars.data() + checksumChars.size(), expected, 16);
        if (parse.ec != std::errc{} || static_cast<uint8_t>(expected) != packetChecksum(packet)) {
            ++checksumFailures;
            if (!noAckMode_) {
                sendAll(socket_, "-");
            }
            continue;
        }

        if (!noAckMode_) {
            sendAll(socket_, "+");
        }
        checksumFailures = 0;
        skippedBytes = 0;

        if (!packet.empty() && packet[0] == 'O' &&
            ((packet.size() - 1) % 2 == 0) &&
            isHexString(std::string_view(packet).substr(1))) {
            log("stdout >> " + decodeHexText(std::string_view(packet).substr(1)));
            continue;
        }

        payload = std::move(packet);
        return true;
    }

    log("remote >> packet read aborted after repeated invalid data\n");
    return false;
}

void GdbRemoteClient::teardownSocket() {
    if (socket_ != invalid_socket_handle) {
        closeSocket(socket_);
        socket_ = invalid_socket_handle;
    }
    resetSessionState();
}

bool GdbRemoteClient::transact(const std::string& payload, std::string& response) {
    if (!sendPacket(payload) || !readPacket(response)) {
        teardownSocket();
        return false;
    }
    return true;
}

bool GdbRemoteClient::initialHandshake() {
    std::string response;

    log("remote >> starting handshake\n");

    if (!transact("qSupported", response)) {
        log("remote >> qSupported failed\n");
        return false;
    }
    log("remote >> qSupported ok\n");

    supportedFeatures_.clear();
    std::stringstream stream(response);
    std::string token;
    while (std::getline(stream, token, ';')) {
        if (token.empty()) {
            continue;
        }
        const auto eq = token.find('=');
        if (eq == std::string::npos) {
            supportedFeatures_[token] = "";
        } else {
            supportedFeatures_[token.substr(0, eq)] = token.substr(eq + 1);
        }
    }

    supportsTargetXml_ = supportedFeatures_.contains("qXfer:features:read+") ||
                         supportedFeatures_.contains("qXfer:features:read");
    supportsMemoryMap_ = supportedFeatures_.contains("qXfer:memory-map:read+") ||
                         supportedFeatures_.contains("qXfer:memory-map:read");

    if (transact("QStartNoAckMode", response) && response == "OK") {
        noAckMode_ = true;
        log("remote >> no-ack mode enabled\n");
    }

    if (transact("vCont?", response)) {
        supportsVCont_ = response.contains("vCont");
        log("remote >> vCont support: " + std::string(supportsVCont_ ? "yes" : "no") + "\n");
    }

    if (registers_.empty()) {
        registers_ = fallbackRegisterLayout();
        registerIndexByName_.clear();
        for (size_t i = 0; i < registers_.size(); ++i) {
            registerIndexByName_[registers_[i].name] = i;
        }
        if (!registers_.empty()) {
            log("remote >> using fallback register layout for the selected architecture\n");
        }
    }

    if (supportsMemoryMap_) {
        log("remote >> loading memory map\n");
        loadMemoryMap();
    }

    log("remote >> handshake complete\n");
    return true;
}

bool GdbRemoteClient::loadFeatureAnnex(const std::string& annex, std::string& xml) {
    xml.clear();
    size_t offset = 0;
    while (true) {
        std::string response;
        const auto chunkLen = 1024;
        std::ostringstream command;
        command << "qXfer:features:read:" << annex << ":" << std::hex << offset << "," << chunkLen;
        if (!transact(command.str(), response)) {
            log("remote >> failed to read feature annex " + annex + "\n");
            return false;
        }
        if (response.empty() || (response[0] != 'm' && response[0] != 'l')) {
            log("remote >> unexpected feature-annex response for " + annex + ": " + response + "\n");
            return false;
        }
        xml += response.substr(1);
        offset += response.size() - 1;
        if (response[0] == 'l') {
            return true;
        }
    }
}

std::string GdbRemoteClient::trim(std::string value) {
    auto isSpace = [](unsigned char c) { return std::isspace(c) != 0; };
    while (!value.empty() && isSpace(static_cast<unsigned char>(value.front()))) {
        value.erase(value.begin());
    }
    while (!value.empty() && isSpace(static_cast<unsigned char>(value.back()))) {
        value.pop_back();
    }
    return value;
}

std::string GdbRemoteClient::attrValue(const std::string& tag, const char* name) {
    const std::string pattern = std::string(name) + "=\"";
    const auto start = tag.find(pattern);
    if (start == std::string::npos) {
        return {};
    }
    const auto valueStart = start + pattern.size();
    const auto valueEnd = tag.find('"', valueStart);
    if (valueEnd == std::string::npos) {
        return {};
    }
    return tag.substr(valueStart, valueEnd - valueStart);
}

bool GdbRemoteClient::parseTargetDescriptionXml(const std::string& xml) {
    std::regex archRegex(R"(<architecture>([^<]+)</architecture>)");
    std::smatch archMatch;
    if (std::regex_search(xml, archMatch, archRegex)) {
        maybeApplyRemoteArchitecture(trim(archMatch[1].str()));
    }

    std::regex regRegex(R"(<reg\b([^>]*)/?>)");
    std::vector<RemoteRegisterDescriptor> descriptors;
    size_t nextRegNum = 0;
    size_t offset = 0;

    for (std::sregex_iterator it(xml.begin(), xml.end(), regRegex), end; it != end; ++it) {
        const auto attrs = (*it)[1].str();
        const auto name = attrValue(attrs, "name");
        const auto bitsizeStr = attrValue(attrs, "bitsize");
        if (name.empty() || bitsizeStr.empty()) {
            continue;
        }

        RemoteRegisterDescriptor desc;
        desc.name = toLowerCase(name);
        desc.type = attrValue(attrs, "type");
        desc.group = attrValue(attrs, "group");
        desc.bitsize = static_cast<size_t>(std::strtoull(bitsizeStr.c_str(), nullptr, 10));
        const auto regnumStr = attrValue(attrs, "regnum");
        if (regnumStr.empty()) {
            desc.regnum = static_cast<uint32_t>(nextRegNum);
        } else {
            desc.regnum = static_cast<uint32_t>(std::strtoul(regnumStr.c_str(), nullptr, 10));
        }
        nextRegNum = static_cast<size_t>(desc.regnum) + 1;
        desc.offset = offset;
        offset += desc.bitsize / 8;
        descriptors.push_back(desc);
    }

    if (descriptors.empty()) {
        return true;
    }

    std::sort(descriptors.begin(), descriptors.end(),
              [](const auto& lhs, const auto& rhs) { return lhs.regnum < rhs.regnum; });
    registers_ = descriptors;
    registerIndexByName_.clear();
    for (size_t i = 0; i < registers_.size(); ++i) {
        registerIndexByName_[registers_[i].name] = i;
    }
    return true;
}

bool GdbRemoteClient::loadTargetDescription() {
    std::string xml;
    if (!loadFeatureAnnex("target.xml", xml)) {
        return false;
    }
    return parseTargetDescriptionXml(xml);
}

bool GdbRemoteClient::parseMemoryMapXml(const std::string& xml) {
    std::regex memRegex(R"xml(<memory[^>]*type="ram"[^>]*start="([^"]+)"[^>]*length="([^"]+)"([^>]*)/?>)xml");
    std::vector<RemoteMemoryRegion> regions;
    for (std::sregex_iterator it(xml.begin(), xml.end(), memRegex), end; it != end; ++it) {
        const auto start = std::strtoull((*it)[1].str().c_str(), nullptr, 0);
        const auto length = std::strtoull((*it)[2].str().c_str(), nullptr, 0);
        const auto tail = (*it)[3].str();
        const auto perms = attrValue(tail, "permissions");

        RemoteMemoryRegion region;
        region.start = start;
        region.end = start + length;
        region.read = perms.empty() || perms.contains('r');
        region.write = perms.contains('w');
        region.execute = perms.contains('x');
        regions.push_back(region);
    }

    memoryRegions_ = std::move(regions);
    return true;
}

bool GdbRemoteClient::loadMemoryMap() {
    if (!supportsMemoryMap_) {
        return false;
    }

    std::string xml;
    size_t offset = 0;
    while (true) {
        std::string response;
        std::ostringstream command;
        command << "qXfer:memory-map:read::" << std::hex << offset << ",1000";
        if (!transact(command.str(), response)) {
            log("remote >> failed to read memory map\n");
            return false;
        }
        if (response.empty() || (response[0] != 'm' && response[0] != 'l')) {
            log("remote >> unexpected memory-map response: " + response + "\n");
            return false;
        }
        xml += response.substr(1);
        offset += response.size() - 1;
        if (response[0] == 'l') {
            break;
        }
    }
    return parseMemoryMapXml(xml);
}

bool GdbRemoteClient::refreshRegisters() {
    if (registers_.empty()) {
        registers_ = fallbackRegisterLayout();
        registerIndexByName_.clear();
        for (size_t i = 0; i < registers_.size(); ++i) {
            registerIndexByName_[registers_[i].name] = i;
        }
        if (registers_.empty()) {
            return false;
        }
    }

    std::string response;
    if (!transact("g", response)) {
        log("remote >> register refresh packet failed\n");
        return false;
    }

    const auto bytes = decodeHexBytes(response);
    if (!bytes.has_value()) {
        log("remote >> register refresh returned non-hex data\n");
        return false;
    }

    registerBlob_ = *bytes;
    return true;
}

void GdbRemoteClient::parseStopRegisters(const std::string& response) {
    cachedRegValues_.clear();
    if (response.starts_with('T') || response.starts_with('S')) {
        size_t pos = 1;
        while (pos < response.size()) {
            auto colon = response.find(':', pos);
            if (colon == std::string::npos) break;
            auto semi = response.find(';', colon);
            if (semi == std::string::npos) semi = response.size();
            unsigned int regnum = 0;
            auto parse = std::from_chars(response.data() + pos, response.data() + colon, regnum, 16);
            if (parse.ec == std::errc{}) {
                std::string valHex(response.data() + colon + 1, semi - colon - 1);
                auto valBytes = decodeHexBytes(valHex);
                if (valBytes.has_value()) {
                    cachedRegValues_[regnum] = *valBytes;
                }
            }
            pos = semi + 1;
        }
    }
}

bool GdbRemoteClient::queryStopReason() {
    std::string response;
    if (!transact("?", response)) {
        log("remote >> stop-reason query failed\n");
        return false;
    }
    lastStopReason_ = response;
    parseStopRegisters(response);
    return true;
}

bool GdbRemoteClient::refreshState() {
    return queryStopReason() && refreshRegisters();
}

bool GdbRemoteClient::resume(const bool singleStep) {
    std::string response;

    const std::string command = supportsVCont_
        ? (singleStep ? "vCont;s" : "vCont;c")
        : (singleStep ? "s" : "c");

    if (!transact(command, response)) {
        log(connected()
            ? "remote >> " + command + " failed (no response)\n"
            : "remote >> target disconnected\n");
        return false;
    }

    if (response.starts_with('E')) {
        log("remote >> resume error: " + response + "\n");
        return false;
    }

    if (response.starts_with('W') || response.starts_with('X')) {
        log("remote >> target exited with: " + response + "\n");
        lastStopReason_ = response;
        return false;
    }

    lastStopReason_ = response;
    parseStopRegisters(response);

    if (!refreshRegisters()) {
        log("remote >> register refresh after resume failed\n");
        return false;
    }

    return true;
}

bool GdbRemoteClient::interrupt() {
    if (!connected()) {
        return false;
    }
    const char ctrlC = 0x03;
    if (!sendAll(socket_, std::string_view(&ctrlC, 1))) {
        teardownSocket();
        return false;
    }
    std::string response;
    if (!readPacket(response)) {
        teardownSocket();
        return false;
    }
    lastStopReason_ = response;
    return refreshRegisters();
}

std::optional<DecodedInstruction> GdbRemoteClient::decodeCurrentInstruction() {
    const auto pc = programCounter();
    if (!pc.has_value()) {
        log("remote >> decode failed: no program counter\n");
        return std::nullopt;
    }

    size_t byteCount = 16;
    switch (codeInformation.archIC) {
        case IC_ARCH_AARCH64:
        case IC_ARCH_ARM:
        case IC_ARCH_THUMBV7M:
            byteCount = 4;
            break;
        default:
            break;
    }

    const auto bytes = readMemory(*pc, byteCount);
    if (!bytes.has_value() || bytes->empty()) {
        std::ostringstream os;
        os << "remote >> decode failed: cannot read memory at 0x" << std::hex << *pc << "\n";
        log(os.str());
        return std::nullopt;
    }

    csh handle{};
    if (cs_open(codeInformation.archCS, codeInformation.modeCS, &handle) != CS_ERR_OK) {
        return std::nullopt;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* instruction = nullptr;
    const auto count = cs_disasm(handle, bytes->data(), bytes->size(), *pc, 1, &instruction);
    if (count == 0 || instruction == nullptr) {
        cs_close(&handle);
        return std::nullopt;
    }

    DecodedInstruction decoded;
    decoded.address = instruction[0].address;
    decoded.size = instruction[0].size;
    decoded.isCall = isCallInstruction(instruction[0]);
    decoded.mnemonic = instruction[0].mnemonic;

    cs_free(instruction, count);
    cs_close(&handle);
    return decoded;
}

bool GdbRemoteClient::isCallInstruction(const cs_insn& instruction) {
    if (instruction.detail != nullptr) {
        for (uint8_t i = 0; i < instruction.detail->groups_count; ++i) {
            if (instruction.detail->groups[i] == CS_GRP_CALL) {
                return true;
            }
        }
    }

    const auto mnemonic = toLowerCase(instruction.mnemonic);
    return mnemonic == "call" || mnemonic == "bl" || mnemonic == "blr" || mnemonic == "blx";
}

bool GdbRemoteClient::hasTrackedBreakpoint(const uint64_t address) const {
    return activeBreakpoints_.contains(address);
}

bool GdbRemoteClient::restart() {
    log("remote >> restart falls back to reconnect; protocol rewind is target-dependent\n");
    return connectTo(remoteConnectionConfig);
}

bool GdbRemoteClient::ensureRegisterDescriptor(const std::string& regName) {
    return registerIndexByName_.contains(toLowerCase(regName));
}

std::optional<std::vector<uint8_t>> GdbRemoteClient::readRegisterSlice(const std::string& regName) {
    if (!ensureRegisterDescriptor(regName)) {
        return std::nullopt;
    }

    const auto& desc = registers_[registerIndexByName_[toLowerCase(regName)]];
    const auto size = desc.bitsize / 8;

    if (auto it = cachedRegValues_.find(desc.regnum); it != cachedRegValues_.end() && it->second.size() == size) {
        return it->second;
    }

    if (registerBlob_.empty() && !refreshRegisters()) {
        return std::nullopt;
    }

    if (desc.offset + size <= registerBlob_.size()) {
        return std::vector<uint8_t>(registerBlob_.begin() + static_cast<std::ptrdiff_t>(desc.offset),
                                    registerBlob_.begin() + static_cast<std::ptrdiff_t>(desc.offset + size));
    }
    return std::nullopt;
}

std::optional<std::vector<uint8_t>> GdbRemoteClient::registerBytes(const std::string& regName) {
    auto result = readRegisterSlice(regName);
    if (!result.has_value()) {
        log("remote >> register read " + regName + " failed\n");
    }
    return result;
}

bool GdbRemoteClient::writeRegisterSlice(const std::string& regName, const std::vector<uint8_t>& bytes) {
    if (!ensureRegisterDescriptor(regName)) {
        return false;
    }

    const auto& desc = registers_[registerIndexByName_[toLowerCase(regName)]];
    if (bytes.size() != desc.bitsize / 8) {
        return false;
    }

    std::ostringstream command;
    command << "P" << std::hex << desc.regnum << "=" << encodeHex(bytes);
    std::string response;
    if (transact(command.str(), response) && response == "OK") {
        if (!registerBlob_.empty() && desc.offset + bytes.size() <= registerBlob_.size()) {
            std::copy(bytes.begin(), bytes.end(),
                      registerBlob_.begin() + static_cast<std::ptrdiff_t>(desc.offset));
        }
        cachedRegValues_.erase(desc.regnum);
        return true;
    }

    if (registerBlob_.empty() && !refreshRegisters()) {
        log("remote >> G fallback: cannot refresh registers for write to " + regName + "\n");
        return false;
    }

    if (desc.offset + bytes.size() > registerBlob_.size()) {
        log("remote >> G fallback: register " + regName + " out of blob bounds\n");
        return false;
    }

    std::copy(bytes.begin(), bytes.end(),
              registerBlob_.begin() + static_cast<std::ptrdiff_t>(desc.offset));

    std::ostringstream gCmd;
    gCmd << "G" << encodeHex(registerBlob_);
    if (!transact(gCmd.str(), response) || response != "OK") {
        log("remote >> G fallback write failed: " + response + "\n");
        return false;
    }

    cachedRegValues_.erase(desc.regnum);
    return true;
}

bool GdbRemoteClient::writeRegister(const std::string& regName, const std::vector<uint8_t>& bytes) {
    return writeRegisterSlice(regName, bytes);
}

std::optional<std::vector<uint8_t>> GdbRemoteClient::readMemory(const uint64_t address, const size_t size) {
    if (!connected()) {
        return std::nullopt;
    }
    std::ostringstream command;
    command << "m" << std::hex << address << "," << size;
    std::string response;
    if (!transact(command.str(), response)) {
        if (connected()) {
            log("remote >> m packet no response\n");
        }
        return std::nullopt;
    }
    if (response.starts_with('E')) {
        return std::nullopt;
    }
    return decodeHexBytes(response);
}

std::optional<std::vector<uint8_t>> GdbRemoteClient::readMemoryWithFallback(
    const uint64_t address, const size_t preferredSize)
{
    static constexpr size_t fallbackSizes[] = {0x4000, 0x2000, 0x1000, 0x800, 0x200, 0x100};

    if (auto result = readMemory(address, preferredSize); result.has_value()) {
        return result;
    }

    for (const auto trySize : fallbackSizes) {
        if (trySize >= preferredSize) continue;
        if (auto result = readMemory(address, trySize); result.has_value()) {
            return result;
        }
    }
    return std::nullopt;
}

bool GdbRemoteClient::writeMemory(const uint64_t address, const std::vector<uint8_t>& bytes) {
    std::ostringstream command;
    command << "M" << std::hex << address << "," << std::dec << bytes.size() << ":" << encodeHex(bytes);
    std::string response;
    return transact(command.str(), response) && response == "OK";
}

bool GdbRemoteClient::insertBreakpoint(const uint64_t address) {
    std::ostringstream command;
    command << "Z0," << std::hex << address << ",1";
    std::string response;
    if (!(transact(command.str(), response) && response == "OK")) {
        return false;
    }
    activeBreakpoints_.insert(address);
    return true;
}

bool GdbRemoteClient::removeBreakpoint(const uint64_t address) {
    std::ostringstream command;
    command << "z0," << std::hex << address << ",1";
    std::string response;
    if (!(transact(command.str(), response) && response == "OK")) {
        return false;
    }
    activeBreakpoints_.erase(address);
    return true;
}

bool GdbRemoteClient::sendMonitorCommand(const std::string& command, std::string& response) {
    if (command.empty()) {
        response.clear();
        return false;
    }
    return transact("qRcmd," + encodeHex(command), response);
}

bool GdbRemoteClient::sendRawPacket(const std::string& payload, std::string& response) {
    return transact(payload, response);
}

std::optional<uint64_t> GdbRemoteClient::archRegisterValue(const char* name) {
    if (name == nullptr) return std::nullopt;
    const auto bytes = readRegisterSlice(name);
    if (!bytes.has_value()) {
        return std::nullopt;
    }
    return littleEndianUint(*bytes);
}

std::optional<uint64_t> GdbRemoteClient::programCounter() {
    return archRegisterValue(archIPStr);
}

std::optional<uint64_t> GdbRemoteClient::stackPointer() {
    return archRegisterValue(archSPStr);
}

std::optional<std::vector<uint8_t>> GdbRemoteClient::readDisassemblyBytes(
    const uint64_t startAddress, const size_t preferredSize)
{
    size_t maxReadableSize = preferredSize;
    for (const auto& region : memoryRegions_) {
        if (!region.execute || startAddress < region.start || startAddress >= region.end) {
            continue;
        }
        maxReadableSize = std::min(maxReadableSize, static_cast<size_t>(region.end - startAddress));
        break;
    }

    std::array<size_t, 6> fallbackSizes = {
        maxReadableSize,
        std::min(maxReadableSize, static_cast<size_t>(0x200)),
        std::min(maxReadableSize, static_cast<size_t>(0x100)),
        std::min(maxReadableSize, static_cast<size_t>(0x80)),
        std::min(maxReadableSize, static_cast<size_t>(0x40)),
        std::min(maxReadableSize, static_cast<size_t>(0x20))
    };

    for (const auto size : fallbackSizes) {
        if (size == 0) {
            continue;
        }
        if (const auto bytes = readMemory(startAddress, size); bytes.has_value()) {
            return bytes;
        }
    }

    return std::nullopt;
}

std::optional<RemoteDisassemblyView> GdbRemoteClient::buildDisassemblyView(
    const size_t instructionCount, const std::optional<uint64_t> startAddress)
{
    const auto pc = programCounter();
    if (!pc.has_value()) {
        return std::nullopt;
    }

    const auto baseAddress = startAddress.value_or(*pc);
    const auto bytes = readDisassemblyBytes(baseAddress, 0x400);
    if (!bytes.has_value() || bytes->empty()) {
        return std::nullopt;
    }

    csh handle{};
    if (cs_open(codeInformation.archCS, codeInformation.modeCS, &handle) != CS_ERR_OK) {
        return std::nullopt;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* instructions = nullptr;
    const auto count = cs_disasm(handle, bytes->data(), bytes->size(), baseAddress, instructionCount, &instructions);
    if (count == 0 || instructions == nullptr) {
        cs_close(&handle);
        return std::nullopt;
    }

    RemoteDisassemblyView view;
    view.startAddress = baseAddress;
    view.currentAddress = *pc;

    std::set<uint64_t> labelTargets;
    std::ostringstream out;

    auto extractBranchTarget = [](const cs_insn& insn) -> std::optional<uint64_t> {
        if (insn.detail == nullptr) return std::nullopt;
        for (uint8_t g = 0; g < insn.detail->groups_count; ++g) {
            const auto grp = insn.detail->groups[g];
            if (grp != CS_GRP_JUMP && grp != CS_GRP_CALL) continue;
            cs_detail* detail = insn.detail;
            switch (codeInformation.archIC) {
                case IC_ARCH_X86_64:
                    for (uint8_t o = 0; o < detail->x86.op_count; ++o)
                        if (detail->x86.operands[o].type == X86_OP_IMM)
                            return detail->x86.operands[o].imm;
                    break;
                case IC_ARCH_AARCH64:
                    for (uint8_t o = 0; o < detail->arm64.op_count; ++o)
                        if (detail->arm64.operands[o].type == ARM64_OP_IMM)
                            return static_cast<uint64_t>(detail->arm64.operands[o].imm);
                    break;
                case IC_ARCH_ARM:
                case IC_ARCH_THUMBV7M:
                    for (uint8_t o = 0; o < detail->arm.op_count; ++o)
                        if (detail->arm.operands[o].type == ARM_OP_IMM)
                            return static_cast<uint64_t>(detail->arm.operands[o].imm);
                    break;
                default: break;
            }
            break;
        }
        return std::nullopt;
    };

    const auto& symbols = globalElfSymbols.addrToName;

    auto symName = [&](uint64_t addr) -> std::string {
        auto it = symbols.find(addr);
        if (it != symbols.end()) return it->second;
        std::ostringstream s;
        s << "0x" << std::hex << std::setw(16) << std::setfill('0') << addr;
        return s.str();
    };

    auto symLabel = [&](uint64_t addr) -> std::string {
        auto it = symbols.find(addr);
        if (it != symbols.end()) return it->second;
        std::ostringstream s;
        s << "0x" << std::hex << addr;
        return s.str();
    };

    for (size_t i = 0; i < count; ++i) {
        const auto lineNumber = static_cast<uint64_t>(i + 1);
        view.addressLineMap[instructions[i].address] = lineNumber;
        if (instructions[i].address == *pc) {
            view.currentLine = lineNumber;
        }

        view.lineAddressLabels[static_cast<int>(i)] = symName(instructions[i].address);
        {
            int64_t off = static_cast<int64_t>(instructions[i].address - baseAddress);
            std::ostringstream os;
            os << (off >= 0 ? "+0x" : "-0x") << std::hex << (off >= 0 ? off : -off);
            view.lineOffsetLabels[static_cast<int>(i)] = os.str();
        }

        if (auto target = extractBranchTarget(instructions[i]); target.has_value()) {
            labelTargets.insert(*target);
        }

        out << instructions[i].mnemonic;
        if (instructions[i].op_str[0] != '\0') {
            out << ' ' << instructions[i].op_str;
        }
        if ((i + 1) < count) {
            out << '\n';
        }
    }

    for (const auto addr : labelTargets) {
        auto it = view.addressLineMap.find(addr);
        if (it == view.addressLineMap.end()) continue;
        view.labelMap[symLabel(addr)] = static_cast<int>(it->second);
    }

    view.text = out.str();

    cs_free(instructions, count);
    cs_close(&handle);
    return view;
}

bool GdbRemoteClient::stepOver() {
    const auto instruction = decodeCurrentInstruction();
    if (!instruction.has_value()) {
        log("remote >> step-over decode failed; falling back to single-step\n");
        return resume(true);
    }

    if (!instruction->isCall || instruction->size == 0) {
        return resume(true);
    }

    const auto nextAddress = instruction->address + instruction->size;
    const bool alreadyTracked = hasTrackedBreakpoint(nextAddress);
    bool insertedTemporaryBreakpoint = false;

    if (!alreadyTracked) {
        insertedTemporaryBreakpoint = insertBreakpoint(nextAddress);
        if (!insertedTemporaryBreakpoint) {
            log("remote >> step-over temp breakpoint failed; falling back to single-step\n");
            return resume(true);
        }
    }

    const bool resumed = resume(false);

    if (insertedTemporaryBreakpoint && !removeBreakpoint(nextAddress)) {
        log("remote >> warning: failed to remove step-over temp breakpoint\n");
    }

    return resumed;
}

}

DebugTargetMode debugTargetMode = DebugTargetMode::Emulation;
RemoteConnectionConfig remoteConnectionConfig{};

void setRemoteLogSink(RemoteLogSink sink) {
    g_logSink = std::move(sink);
}

void setRemoteArchHook(RemoteArchHook hook) {
    g_archHook = std::move(hook);
}

bool useRemoteDebugging() {
    return debugTargetMode == DebugTargetMode::RemoteGdb;
}

bool remoteDebugConnected() {
    std::lock_guard lock(clientMutex);
    return client.connected();
}

void remoteClearCachedState() {
    std::lock_guard lock(clientMutex);
    client.clearCachedState();
}

bool connectRemoteDebugSession() {
    std::lock_guard lock(clientMutex);
    return client.connectTo(remoteConnectionConfig);
}

void disconnectRemoteDebugSession() {
    std::lock_guard lock(clientMutex);
    client.disconnect();
}

bool remoteRestartSession() {
    std::lock_guard lock(clientMutex);
    return client.restart();
}

bool remotePause() {
    std::lock_guard lock(clientMutex);
    return client.interrupt();
}

bool remoteContinue() {
    std::lock_guard lock(clientMutex);
    return client.resume(false);
}

bool remoteStep() {
    std::lock_guard lock(clientMutex);
    return client.resume(true);
}

bool remoteStepOver() {
    std::lock_guard lock(clientMutex);
    return client.stepOver();
}

bool remoteRefreshState() {
    std::lock_guard lock(clientMutex);
    return client.refreshState();
}

std::optional<std::vector<uint8_t>> remoteReadRegister(const std::string& regName) {
    std::lock_guard lock(clientMutex);
    return client.registerBytes(regName);
}

bool remoteWriteRegister(const std::string& regName, const std::vector<uint8_t>& bytes) {
    std::lock_guard lock(clientMutex);
    return client.writeRegister(regName, bytes);
}

std::optional<std::vector<uint8_t>> remoteReadMemory(const uint64_t address, const size_t size) {
    std::lock_guard lock(clientMutex);
    return client.readMemory(address, size);
}

std::optional<std::vector<uint8_t>> remoteReadMemoryWithFallback(const uint64_t address, const size_t preferredSize) {
    std::lock_guard lock(clientMutex);
    return client.readMemoryWithFallback(address, preferredSize);
}

bool remoteWriteMemory(const uint64_t address, const std::vector<uint8_t>& bytes) {
    std::lock_guard lock(clientMutex);
    return client.writeMemory(address, bytes);
}

bool remoteAddBreakpoint(const uint64_t address) {
    std::lock_guard lock(clientMutex);
    return client.insertBreakpoint(address);
}

bool remoteRemoveBreakpoint(const uint64_t address) {
    std::lock_guard lock(clientMutex);
    return client.removeBreakpoint(address);
}

std::vector<RemoteMemoryRegion> remoteMemoryRegions() {
    std::lock_guard lock(clientMutex);
    return client.memoryRegions();
}

bool remoteTargetSupportsMemoryMap() {
    std::lock_guard lock(clientMutex);
    return client.supportsMemoryMap();
}

bool remoteTargetSupportsTargetXml() {
    std::lock_guard lock(clientMutex);
    return client.supportsTargetXml();
}

std::optional<RemoteDisassemblyView> remoteBuildDisassemblyView(
    const size_t instructionCount, const std::optional<uint64_t> startAddress)
{
    std::lock_guard lock(clientMutex);
    return client.buildDisassemblyView(instructionCount, startAddress);
}

std::optional<uint64_t> remoteProgramCounter() {
    std::lock_guard lock(clientMutex);
    return client.programCounter();
}

std::optional<uint64_t> remoteStackPointer() {
    std::lock_guard lock(clientMutex);
    return client.stackPointer();
}

bool remoteSendMonitorCommand(const std::string& command, std::string& response) {
    std::lock_guard lock(clientMutex);
    return client.sendMonitorCommand(command, response);
}

bool remoteSendRawPacket(const std::string& payload, std::string& response) {
    std::lock_guard lock(clientMutex);
    return client.sendRawPacket(payload, response);
}

std::string remoteConnectionLabel() {
    std::ostringstream out;
    out << "Remote " << remoteConnectionConfig.host << ":" << remoteConnectionConfig.port;
    return out.str();
}

std::string remoteLastStopReason() {
    std::lock_guard lock(clientMutex);
    return client.lastStopReason();
}

bool remoteLoadSymbolFile(const std::string& path) {
    auto symbols = loadElfSymbols(path);
    if (symbols.addrToName.empty()) return false;
    globalElfSymbols = std::move(symbols);
    return true;
}

const ElfSymbols& remoteLoadedSymbols() {
    return globalElfSymbols;
}

}
