#include "linuxProcess.hpp"

#include "interpreter/interpreter.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

#if defined(__linux__) && !defined(__EMSCRIPTEN__)
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#endif

extern void consoleWriteThreadSafe(const std::string& text);

namespace {

constexpr uint64_t kPageSize = 0x1000;
constexpr uint64_t kLinuxStackTop = 0x7ffffff00000ULL;
constexpr uint64_t kLinuxStackSize = 8ULL * 1024ULL * 1024ULL;
constexpr uint64_t kInitialStackZeroSize = 128ULL * 1024ULL;
constexpr uint64_t kDefaultMmapBase = 0x700000000000ULL;
constexpr uint64_t kMaxGuestString = 4096;
constexpr int kEmulatedPid = 4242;
constexpr int kEmulatedUid = 1000;
constexpr int kEmulatedGid = 1000;

constexpr uint64_t kAtNull = 0;
constexpr uint64_t kAtPhdr = 3;
constexpr uint64_t kAtPhent = 4;
constexpr uint64_t kAtPhnum = 5;
constexpr uint64_t kAtPagesz = 6;
constexpr uint64_t kAtBase = 7;
constexpr uint64_t kAtFlags = 8;
constexpr uint64_t kAtEntry = 9;
constexpr uint64_t kAtUid = 11;
constexpr uint64_t kAtEuid = 12;
constexpr uint64_t kAtGid = 13;
constexpr uint64_t kAtEgid = 14;
constexpr uint64_t kAtPlatform = 15;
constexpr uint64_t kAtHwcap = 16;
constexpr uint64_t kAtClktck = 17;
constexpr uint64_t kAtSecure = 23;
constexpr uint64_t kAtRandom = 25;
constexpr uint64_t kAtHwcap2 = 26;
constexpr uint64_t kAtExecfn = 31;
constexpr uint64_t kAtMinsigstksz = 51;

constexpr uint64_t kSysRead = 0;
constexpr uint64_t kSysWrite = 1;
constexpr uint64_t kSysOpen = 2;
constexpr uint64_t kSysClose = 3;
constexpr uint64_t kSysFstat = 5;
constexpr uint64_t kSysLseek = 8;
constexpr uint64_t kSysMmap = 9;
constexpr uint64_t kSysMprotect = 10;
constexpr uint64_t kSysMunmap = 11;
constexpr uint64_t kSysBrk = 12;
constexpr uint64_t kSysRtSigaction = 13;
constexpr uint64_t kSysRtSigprocmask = 14;
constexpr uint64_t kSysIoctl = 16;
constexpr uint64_t kSysPread64 = 17;
constexpr uint64_t kSysWritev = 20;
constexpr uint64_t kSysAccess = 21;
constexpr uint64_t kSysMremap = 25;
constexpr uint64_t kSysMadvise = 28;
constexpr uint64_t kSysGetpid = 39;
constexpr uint64_t kSysSocket = 41;
constexpr uint64_t kSysClone = 56;
constexpr uint64_t kSysExit = 60;
constexpr uint64_t kSysUname = 63;
constexpr uint64_t kSysFcntl = 72;
constexpr uint64_t kSysReadlink = 89;
constexpr uint64_t kSysGetcwd = 79;
constexpr uint64_t kSysGettimeofday = 96;
constexpr uint64_t kSysGetuid = 102;
constexpr uint64_t kSysGetgid = 104;
constexpr uint64_t kSysGeteuid = 107;
constexpr uint64_t kSysGetegid = 108;
constexpr uint64_t kSysArchPrctl = 158;
constexpr uint64_t kSysSetTidAddress = 218;
constexpr uint64_t kSysFutex = 202;
constexpr uint64_t kSysClockGettime = 228;
constexpr uint64_t kSysExitGroup = 231;
constexpr uint64_t kSysOpenat = 257;
constexpr uint64_t kSysNewfstatat = 262;
constexpr uint64_t kSysReadlinkat = 267;
constexpr uint64_t kSysFaccessat = 269;
constexpr uint64_t kSysSetRobustList = 273;
constexpr uint64_t kSysPrlimit64 = 302;
constexpr uint64_t kSysGetrandom = 318;
constexpr uint64_t kSysRseq = 334;

constexpr int kArchSetFs = 0x1002;
constexpr int kArchGetFs = 0x1003;
constexpr int kProtRead = 0x1;
constexpr int kProtWrite = 0x2;
constexpr int kProtExec = 0x4;
constexpr int kMapFixed = 0x10;
constexpr int kMapAnonymous = 0x20;
constexpr int kSeekSet = 0;
constexpr int kSeekCur = 1;
constexpr int kSeekEnd = 2;

struct GuestFile {
    std::string path;
    std::vector<uint8_t> data;
    uint64_t offset = 0;
    bool random = false;
};

struct LinuxProcessState {
    bool active = false;
    bool exited = false;
    int exitCode = 0;
    LinuxProcessImage image;
    uint64_t brkCurrent = 0;
    uint64_t brkMappedEnd = 0;
    uint64_t mmapNext = kDefaultMmapBase;
    std::map<int, GuestFile> files;
    int nextFd = 3;
    std::unordered_set<uint64_t> warnedSyscalls;
};

LinuxProcessState gProcess;

uint64_t pageFloor(const uint64_t value)
{
    return value & ~(kPageSize - 1);
}

uint64_t pageCeil(const uint64_t value)
{
    return (value + kPageSize - 1) & ~(kPageSize - 1);
}

uint64_t alignDown(const uint64_t value, const uint64_t alignment)
{
    return value & ~(alignment - 1);
}

std::string formatAddress(const uint64_t value)
{
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}

MemoryProtection protectionFromLinuxProt(const uint64_t prot)
{
    const bool read = (prot & kProtRead) != 0;
    const bool write = (prot & kProtWrite) != 0;
    const bool execute = (prot & kProtExec) != 0;

    if (read && write && execute) return ExecuteReadWrite;
    if (read && write) return ReadWrite;
    if (read && execute) return ExecuteRead;
    if (execute) return ExecuteOnly;
    if (read) return ReadOnly;
    if (write) return ReadWrite;
    return NoAccess;
}

int64_t negativeErrno(const int error)
{
    return -static_cast<int64_t>(error);
}

void setSyscallReturn(Icicle* vm, const int64_t value)
{
    if (vm != nullptr) {
        icicle_reg_write(vm, "rax", static_cast<uint64_t>(value));
    }
}

bool writeGuestBytes(Icicle* vm, const uint64_t address, const void* data, const size_t size)
{
    if (size == 0) {
        return true;
    }
    if (vm == nullptr || data == nullptr) {
        return false;
    }
    return icicle_mem_write(vm, address, static_cast<const uint8_t*>(data), size) == 0;
}

bool writeGuestU64(Icicle* vm, const uint64_t address, const uint64_t value)
{
    std::array<uint8_t, 8> bytes{};
    for (size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<uint8_t>((value >> (i * 8)) & 0xff);
    }
    return writeGuestBytes(vm, address, bytes.data(), bytes.size());
}

std::optional<uint64_t> readGuestU64(Icicle* vm, const uint64_t address)
{
    size_t outSize = 0;
    unsigned char* raw = icicle_mem_read(vm, address, sizeof(uint64_t), &outSize);
    if (raw == nullptr || outSize < sizeof(uint64_t)) {
        if (raw != nullptr) {
            icicle_free_buffer(raw, outSize);
        }
        return std::nullopt;
    }

    uint64_t value = 0;
    for (size_t i = 0; i < sizeof(uint64_t); ++i) {
        value |= static_cast<uint64_t>(raw[i]) << (i * 8);
    }
    icicle_free_buffer(raw, outSize);
    return value;
}

std::optional<std::vector<uint8_t>> readGuestBytes(Icicle* vm, const uint64_t address, const size_t size)
{
    if (size == 0) {
        return std::vector<uint8_t>{};
    }

    size_t outSize = 0;
    unsigned char* raw = icicle_mem_read(vm, address, size, &outSize);
    if (raw == nullptr) {
        return std::nullopt;
    }

    std::vector<uint8_t> bytes(raw, raw + outSize);
    icicle_free_buffer(raw, outSize);
    return bytes;
}

std::optional<std::string> readGuestString(Icicle* vm, const uint64_t address)
{
    std::string out;
    out.reserve(64);

    for (uint64_t i = 0; i < kMaxGuestString; ++i) {
        size_t outSize = 0;
        unsigned char* raw = icicle_mem_read(vm, address + i, 1, &outSize);
        if (raw == nullptr || outSize != 1) {
            if (raw != nullptr) {
                icicle_free_buffer(raw, outSize);
            }
            return std::nullopt;
        }

        const char c = static_cast<char>(raw[0]);
        icicle_free_buffer(raw, outSize);
        if (c == '\0') {
            return out;
        }
        out.push_back(c);
    }

    return std::nullopt;
}

bool readHostFile(const std::string& path, std::vector<uint8_t>& bytes)
{
    std::ifstream input(path, std::ios::binary);
    if (!input.good()) {
        return false;
    }

    input.seekg(0, std::ios::end);
    const auto size = input.tellg();
    if (size < 0) {
        return false;
    }
    input.seekg(0, std::ios::beg);

    bytes.resize(static_cast<size_t>(size));
    if (!bytes.empty()) {
        input.read(reinterpret_cast<char*>(bytes.data()), size);
    }
    return input.good() || input.eof();
}

std::string normalizeGuestPath(const std::string& path)
{
    if (path == "/proc/self/exe" || path == "/proc/4242/exe") {
        return gProcess.image.path;
    }
    return path;
}

bool guestPathExists(const std::string& path)
{
    const auto normalized = normalizeGuestPath(path);
    return normalized == "/dev/urandom" || normalized == "/dev/random" ||
           std::filesystem::exists(normalized);
}

int openGuestFile(const std::string& path)
{
    const auto normalized = normalizeGuestPath(path);
    GuestFile file;
    file.path = normalized;

    if (normalized == "/dev/urandom" || normalized == "/dev/random") {
        file.random = true;
    } else if (!readHostFile(normalized, file.data)) {
        return -1;
    }

    const int fd = gProcess.nextFd++;
    gProcess.files[fd] = std::move(file);
    return fd;
}

GuestFile* lookupFile(const int fd)
{
    auto it = gProcess.files.find(fd);
    return it != gProcess.files.end() ? &it->second : nullptr;
}

void fillDeterministicRandom(uint8_t* data, const size_t size)
{
    uint64_t x = 0x9e3779b97f4a7c15ULL;
    for (size_t i = 0; i < size; ++i) {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        data[i] = static_cast<uint8_t>((x * 0x2545f4914f6cdd1dULL) >> 56);
    }
}

int64_t readFromGuestFile(const int fd, const uint64_t buffer, const size_t count)
{
    if (fd == 0) {
        return 0;
    }

    auto* file = lookupFile(fd);
    if (file == nullptr) {
        return negativeErrno(EBADF);
    }

    std::vector<uint8_t> bytes(count);
    size_t readCount = 0;
    if (file->random) {
        fillDeterministicRandom(bytes.data(), bytes.size());
        readCount = bytes.size();
    } else if (file->offset < file->data.size()) {
        readCount = std::min<size_t>(count, file->data.size() - static_cast<size_t>(file->offset));
        std::memcpy(bytes.data(), file->data.data() + file->offset, readCount);
        file->offset += readCount;
    }

    if (readCount > 0 && !writeGuestBytes(icicle, buffer, bytes.data(), readCount)) {
        return negativeErrno(EFAULT);
    }

    return static_cast<int64_t>(readCount);
}

int64_t preadFromGuestFile(const int fd, const uint64_t buffer, const size_t count, const uint64_t offset)
{
    auto* file = lookupFile(fd);
    if (file == nullptr) {
        return negativeErrno(EBADF);
    }

    std::vector<uint8_t> bytes(count);
    size_t readCount = 0;
    if (file->random) {
        fillDeterministicRandom(bytes.data(), bytes.size());
        readCount = bytes.size();
    } else if (offset < file->data.size()) {
        readCount = std::min<size_t>(count, file->data.size() - static_cast<size_t>(offset));
        std::memcpy(bytes.data(), file->data.data() + offset, readCount);
    }

    if (readCount > 0 && !writeGuestBytes(icicle, buffer, bytes.data(), readCount)) {
        return negativeErrno(EFAULT);
    }

    return static_cast<int64_t>(readCount);
}

int64_t writeGuestOutput(const int fd, const uint64_t buffer, const size_t count)
{
    if (fd != 1 && fd != 2) {
        return negativeErrno(EBADF);
    }

    const auto bytes = readGuestBytes(icicle, buffer, count);
    if (!bytes.has_value()) {
        return negativeErrno(EFAULT);
    }

    const std::string text(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    consoleWriteThreadSafe(std::string(fd == 2 ? "stderr >> " : "stdout >> ") + text);
    return static_cast<int64_t>(bytes->size());
}

int64_t writeGuestOutputVector(const int fd, const uint64_t iov, const uint64_t iovCount)
{
    if (iovCount > 1024) {
        return negativeErrno(EINVAL);
    }

    int64_t total = 0;
    for (uint64_t i = 0; i < iovCount; ++i) {
        const auto base = readGuestU64(icicle, iov + (i * 16));
        const auto len = readGuestU64(icicle, iov + (i * 16) + 8);
        if (!base.has_value() || !len.has_value()) {
            return negativeErrno(EFAULT);
        }

        const auto wrote = writeGuestOutput(fd, *base, static_cast<size_t>(*len));
        if (wrote < 0) {
            return wrote;
        }
        total += wrote;
    }
    return total;
}

int64_t handleBrk(const uint64_t requested)
{
    if (requested == 0) {
        return static_cast<int64_t>(gProcess.brkCurrent);
    }

    if (requested < gProcess.image.brkStart) {
        return static_cast<int64_t>(gProcess.brkCurrent);
    }

    const uint64_t newMappedEnd = pageCeil(requested);
    if (newMappedEnd > gProcess.brkMappedEnd) {
        const uint64_t mapStart = gProcess.brkMappedEnd;
        const uint64_t mapSize = newMappedEnd - mapStart;
        if (icicle_mem_map(icicle, mapStart, mapSize, ReadWrite) != 0) {
            return static_cast<int64_t>(gProcess.brkCurrent);
        }
        gProcess.brkMappedEnd = newMappedEnd;
    }

    gProcess.brkCurrent = requested;
    return static_cast<int64_t>(gProcess.brkCurrent);
}

int64_t handleMmap(const SyscallArgs* args)
{
    const uint64_t requestedAddress = args->arg0;
    const uint64_t requestedSize = args->arg1;
    const uint64_t prot = args->arg2;
    const uint64_t flags = args->arg3;
    const int fd = static_cast<int>(args->arg4);
    const uint64_t fileOffset = args->arg5;

    if (requestedSize == 0) {
        return negativeErrno(EINVAL);
    }

    GuestFile* file = nullptr;
    if ((flags & kMapAnonymous) == 0 && fd >= 0) {
        file = lookupFile(fd);
        if (file == nullptr) {
            return negativeErrno(EBADF);
        }
    }

    const uint64_t mapSize = pageCeil(requestedSize);
    uint64_t address = 0;
    if ((flags & kMapFixed) != 0 && requestedAddress != 0) {
        address = pageFloor(requestedAddress);
        icicle_mem_unmap(icicle, address, mapSize);
    } else if (requestedAddress != 0) {
        address = pageFloor(requestedAddress);
    } else {
        address = pageCeil(gProcess.mmapNext);
        gProcess.mmapNext = address + mapSize + kPageSize;
    }

    const auto protection = protectionFromLinuxProt(prot);
    if (icicle_mem_map(icicle, address, mapSize, protection) != 0) {
        return negativeErrno(ENOMEM);
    }

    std::array<uint8_t, kPageSize> zeros{};
    for (uint64_t page = address; page < address + mapSize; page += kPageSize) {
        icicle_mem_write(icicle, page, zeros.data(), zeros.size());
    }

    if (file != nullptr) {
        if (!file->random && fileOffset < file->data.size()) {
            const size_t readCount = std::min<size_t>(
                static_cast<size_t>(requestedSize),
                file->data.size() - static_cast<size_t>(fileOffset));
            if (readCount > 0 &&
                icicle_mem_write(icicle, requestedAddress != 0 ? requestedAddress : address,
                                 file->data.data() + fileOffset, readCount) != 0) {
                return negativeErrno(EFAULT);
            }
        }
    }

    return static_cast<int64_t>(requestedAddress != 0 ? requestedAddress : address);
}

int64_t handleMprotect(const uint64_t address, const uint64_t size, const uint64_t prot)
{
    if (size == 0) {
        return 0;
    }

    const uint64_t mapStart = pageFloor(address);
    const uint64_t mapSize = pageCeil((address - mapStart) + size);
    return icicle_mem_protect(icicle, mapStart, mapSize, protectionFromLinuxProt(prot)) == 0
        ? 0
        : negativeErrno(EINVAL);
}

int64_t handleMunmap(const uint64_t address, const uint64_t size)
{
    if (size == 0) {
        return negativeErrno(EINVAL);
    }

    const uint64_t mapStart = pageFloor(address);
    const uint64_t mapSize = pageCeil((address - mapStart) + size);
    icicle_mem_unmap(icicle, mapStart, mapSize);
    return 0;
}

int64_t handleLseek(const int fd, const int64_t offset, const int whence)
{
    auto* file = lookupFile(fd);
    if (file == nullptr) {
        return negativeErrno(EBADF);
    }

    int64_t base = 0;
    if (whence == kSeekSet) {
        base = 0;
    } else if (whence == kSeekCur) {
        base = static_cast<int64_t>(file->offset);
    } else if (whence == kSeekEnd) {
        base = static_cast<int64_t>(file->data.size());
    } else {
        return negativeErrno(EINVAL);
    }

    const int64_t next = base + offset;
    if (next < 0) {
        return negativeErrno(EINVAL);
    }

    file->offset = static_cast<uint64_t>(next);
    return next;
}

int64_t writeNativeStat(const std::string& path, const uint64_t guestAddress)
{
#if defined(__linux__) && !defined(__EMSCRIPTEN__)
    struct stat st {};
    const auto normalized = normalizeGuestPath(path);
    if (normalized == "/dev/urandom" || normalized == "/dev/random") {
        st.st_mode = S_IFCHR | 0444;
        st.st_nlink = 1;
        st.st_blksize = 4096;
    } else if (::stat(normalized.c_str(), &st) != 0) {
        return negativeErrno(errno);
    }

    return writeGuestBytes(icicle, guestAddress, &st, sizeof(st)) ? 0 : negativeErrno(EFAULT);
#else
    (void)path;
    (void)guestAddress;
    return negativeErrno(ENOSYS);
#endif
}

int64_t handleFstat(const int fd, const uint64_t guestAddress)
{
    if (fd >= 0 && fd <= 2) {
#if defined(__linux__) && !defined(__EMSCRIPTEN__)
        struct stat st {};
        st.st_mode = S_IFCHR | 0600;
        st.st_nlink = 1;
        st.st_blksize = 4096;
        return writeGuestBytes(icicle, guestAddress, &st, sizeof(st)) ? 0 : negativeErrno(EFAULT);
#else
        return negativeErrno(ENOSYS);
#endif
    }

    const auto* file = lookupFile(fd);
    if (file == nullptr) {
        return negativeErrno(EBADF);
    }

    return writeNativeStat(file->path, guestAddress);
}

int64_t handleReadlink(const std::string& path, const uint64_t buffer, const uint64_t size)
{
    if (size == 0) {
        return negativeErrno(EINVAL);
    }

    std::string target;
    if (path == "/proc/self/exe" || path == "/proc/4242/exe") {
        target = gProcess.image.path;
    } else {
#if defined(__linux__) && !defined(__EMSCRIPTEN__)
        std::array<char, 4096> hostTarget{};
        const ssize_t readLen = ::readlink(path.c_str(), hostTarget.data(), hostTarget.size());
        if (readLen < 0) {
            return negativeErrno(errno);
        }
        target.assign(hostTarget.data(), static_cast<size_t>(readLen));
#else
        return negativeErrno(EINVAL);
#endif
    }

    const size_t count = std::min<size_t>(target.size(), static_cast<size_t>(size));
    return writeGuestBytes(icicle, buffer, target.data(), count) ? static_cast<int64_t>(count)
                                                                : negativeErrno(EFAULT);
}

int64_t handleClockGettime(const uint64_t guestAddress)
{
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(now);
    const auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(now - seconds);

    std::array<uint8_t, 16> timespec{};
    const uint64_t sec = static_cast<uint64_t>(seconds.count());
    const uint64_t nsec = static_cast<uint64_t>(nanoseconds.count());
    std::memcpy(timespec.data(), &sec, sizeof(sec));
    std::memcpy(timespec.data() + 8, &nsec, sizeof(nsec));
    return writeGuestBytes(icicle, guestAddress, timespec.data(), timespec.size()) ? 0 : negativeErrno(EFAULT);
}

int64_t handleGettimeofday(const uint64_t timevalAddress)
{
    if (timevalAddress == 0) {
        return 0;
    }

    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(now);
    const auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(now - seconds);

    std::array<uint8_t, 16> timeval{};
    const uint64_t sec = static_cast<uint64_t>(seconds.count());
    const uint64_t usec = static_cast<uint64_t>(microseconds.count());
    std::memcpy(timeval.data(), &sec, sizeof(sec));
    std::memcpy(timeval.data() + 8, &usec, sizeof(usec));
    return writeGuestBytes(icicle, timevalAddress, timeval.data(), timeval.size()) ? 0 : negativeErrno(EFAULT);
}

int64_t handleUname(const uint64_t guestAddress)
{
    std::array<char, 390> uts{};
    auto copyField = [&](const size_t index, const std::string& value) {
        constexpr size_t fieldSize = 65;
        std::memcpy(uts.data() + (index * fieldSize), value.c_str(), std::min(value.size(), fieldSize - 1));
    };

    copyField(0, "Linux");
    copyField(1, "zathura");
    copyField(2, "6.10.0-zathura");
    copyField(3, "#1 ZathuraDbg");
    copyField(4, "x86_64");
    copyField(5, "localdomain");
    return writeGuestBytes(icicle, guestAddress, uts.data(), uts.size()) ? 0 : negativeErrno(EFAULT);
}

int64_t handlePrlimit64(const uint64_t oldLimitAddress)
{
    if (oldLimitAddress == 0) {
        return 0;
    }

    std::array<uint8_t, 16> rlimit{};
    const uint64_t soft = kLinuxStackSize;
    const uint64_t hard = kLinuxStackSize;
    std::memcpy(rlimit.data(), &soft, sizeof(soft));
    std::memcpy(rlimit.data() + 8, &hard, sizeof(hard));
    return writeGuestBytes(icicle, oldLimitAddress, rlimit.data(), rlimit.size()) ? 0 : negativeErrno(EFAULT);
}

int64_t handleArchPrctl(const uint64_t code, const uint64_t address)
{
    if (code == kArchSetFs) {
        return icicle_reg_write(icicle, "fs_base", address) == 0 ? 0 : negativeErrno(EINVAL);
    }

    if (code == kArchGetFs) {
        uint64_t fsBase = 0;
        if (icicle_reg_read(icicle, "fs_base", &fsBase) != 0) {
            return negativeErrno(EINVAL);
        }
        return writeGuestU64(icicle, address, fsBase) ? 0 : negativeErrno(EFAULT);
    }

    return negativeErrno(EINVAL);
}

int64_t handleFcntl(const int fd, const uint64_t cmd)
{
    if ((fd < 0 || fd > 2) && lookupFile(fd) == nullptr) {
        return negativeErrno(EBADF);
    }

    if (cmd == 1) {
        return 0;
    }
    if (cmd == 2 || cmd == 3) {
        return 0;
    }
    return 0;
}

void warnUnsupportedSyscallOnce(const uint64_t syscallNumber)
{
    if (gProcess.warnedSyscalls.insert(syscallNumber).second) {
        consoleWriteThreadSafe("linux >> unsupported syscall " + std::to_string(syscallNumber) + " -> -ENOSYS\n");
    }
}

std::vector<std::string> defaultEnvironment()
{
    return {
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME=/",
        "USER=rc",
        "LOGNAME=rc",
        "LANG=C",
        "TERM=xterm-256color",
    };
}

} // namespace

bool configureLinuxProcess(const LinuxProcessImage& image)
{
    gProcess = LinuxProcessState{};
    gProcess.active = true;
    gProcess.image = image;
    gProcess.brkCurrent = image.brkStart;
    gProcess.brkMappedEnd = pageCeil(image.brkStart);
    gProcess.mmapNext = kDefaultMmapBase;
    return true;
}

bool setupLinuxProcessStack(Icicle* vm)
{
    if (vm == nullptr || !gProcess.active) {
        return false;
    }

    STACK_ADDRESS = kLinuxStackTop - kLinuxStackSize;
    STACK_SIZE = kLinuxStackSize;

    if (icicle_mem_map(vm, STACK_ADDRESS, STACK_SIZE, ReadWrite) != 0) {
        consoleWriteThreadSafe("linux >> failed to map process stack at " + formatAddress(STACK_ADDRESS) + "\n");
        return false;
    }

    const uint64_t zeroSize = std::min(kInitialStackZeroSize, kLinuxStackSize);
    const uint64_t zeroStart = kLinuxStackTop - zeroSize;
    std::array<uint8_t, kPageSize> zeros{};
    for (uint64_t address = zeroStart; address < kLinuxStackTop; address += kPageSize) {
        if (icicle_mem_write(vm, address, zeros.data(), zeros.size()) != 0) {
            consoleWriteThreadSafe("linux >> failed to zero process stack\n");
            return false;
        }
    }

    const std::vector<std::string> argv = {gProcess.image.path};
    const auto envp = defaultEnvironment();
    std::vector<uint64_t> argvAddresses;
    std::vector<uint64_t> envpAddresses;

    uint64_t cursor = kLinuxStackTop;
    auto pushString = [&](const std::string& value) -> std::optional<uint64_t> {
        cursor -= value.size() + 1;
        if (!writeGuestBytes(vm, cursor, value.c_str(), value.size() + 1)) {
            return std::nullopt;
        }
        return cursor;
    };

    for (auto it = argv.rbegin(); it != argv.rend(); ++it) {
        auto address = pushString(*it);
        if (!address.has_value()) return false;
        argvAddresses.push_back(*address);
    }
    std::reverse(argvAddresses.begin(), argvAddresses.end());

    for (auto it = envp.rbegin(); it != envp.rend(); ++it) {
        auto address = pushString(*it);
        if (!address.has_value()) return false;
        envpAddresses.push_back(*address);
    }
    std::reverse(envpAddresses.begin(), envpAddresses.end());

    const auto execfnAddress = pushString(gProcess.image.path);
    const auto platformAddress = pushString("x86_64");
    if (!execfnAddress.has_value() || !platformAddress.has_value()) {
        return false;
    }

    cursor = alignDown(cursor - 16, 16);
    std::array<uint8_t, 16> randomBytes{};
    fillDeterministicRandom(randomBytes.data(), randomBytes.size());
    if (!writeGuestBytes(vm, cursor, randomBytes.data(), randomBytes.size())) {
        return false;
    }
    const uint64_t randomAddress = cursor;

    std::vector<std::pair<uint64_t, uint64_t>> auxv = {
        {kAtPhdr, gProcess.image.programHeaders},
        {kAtPhent, gProcess.image.programHeaderEntrySize},
        {kAtPhnum, gProcess.image.programHeaderCount},
        {kAtPagesz, kPageSize},
        {kAtBase, gProcess.image.interpreterBase},
        {kAtFlags, 0},
        {kAtEntry, gProcess.image.programEntry},
        {kAtUid, kEmulatedUid},
        {kAtEuid, kEmulatedUid},
        {kAtGid, kEmulatedGid},
        {kAtEgid, kEmulatedGid},
        {kAtSecure, 0},
        {kAtRandom, randomAddress},
        {kAtHwcap, 0},
        {kAtHwcap2, 0},
        {kAtClktck, 100},
        {kAtPlatform, *platformAddress},
        {kAtExecfn, *execfnAddress},
        {kAtMinsigstksz, 2048},
        {kAtNull, 0},
    };

    std::vector<uint64_t> words;
    words.push_back(argvAddresses.size());
    words.insert(words.end(), argvAddresses.begin(), argvAddresses.end());
    words.push_back(0);
    words.insert(words.end(), envpAddresses.begin(), envpAddresses.end());
    words.push_back(0);
    for (const auto& [type, value] : auxv) {
        words.push_back(type);
        words.push_back(value);
    }

    cursor = alignDown(cursor - (words.size() * sizeof(uint64_t)), 16);
    for (size_t i = 0; i < words.size(); ++i) {
        if (!writeGuestU64(vm, cursor + (i * sizeof(uint64_t)), words[i])) {
            return false;
        }
    }

    icicle_reg_write(vm, "rsp", cursor);
    icicle_reg_write(vm, "rbp", cursor);
    return true;
}

void clearLinuxProcess()
{
    gProcess = LinuxProcessState{};
    STACK_ADDRESS = DEFAULT_STACK_ADDRESS;
    STACK_SIZE = 64ULL * 1024ULL;
}

bool linuxProcessActive()
{
    return gProcess.active;
}

bool linuxProcessExited()
{
    return gProcess.active && gProcess.exited;
}

int linuxProcessExitCode()
{
    return gProcess.exitCode;
}

int handleLinuxProcessSyscall(void* data, const uint64_t syscallNumber, const SyscallArgs* args)
{
    auto* vm = static_cast<Icicle*>(data);
    if (vm == nullptr || args == nullptr || !gProcess.active) {
        return 0;
    }

    icicle = vm;
    int64_t result = 0;
    int hookResult = 0;

    switch (syscallNumber) {
        case kSysRead:
            result = readFromGuestFile(static_cast<int>(args->arg0), args->arg1, static_cast<size_t>(args->arg2));
            break;
        case kSysWrite:
            result = writeGuestOutput(static_cast<int>(args->arg0), args->arg1, static_cast<size_t>(args->arg2));
            break;
        case kSysOpen: {
            const auto path = readGuestString(vm, args->arg0);
            if (!path.has_value()) {
                result = negativeErrno(EFAULT);
            } else if (const int fd = openGuestFile(*path); fd >= 0) {
                result = fd;
            } else {
                result = negativeErrno(ENOENT);
            }
            break;
        }
        case kSysOpenat: {
            const auto path = readGuestString(vm, args->arg1);
            if (!path.has_value()) {
                result = negativeErrno(EFAULT);
            } else if (const int fd = openGuestFile(*path); fd >= 0) {
                result = fd;
            } else {
                result = negativeErrno(ENOENT);
            }
            break;
        }
        case kSysClose:
            if (args->arg0 <= 2) {
                result = 0;
            } else {
                result = gProcess.files.erase(static_cast<int>(args->arg0)) ? 0 : negativeErrno(EBADF);
            }
            break;
        case kSysFstat:
            result = handleFstat(static_cast<int>(args->arg0), args->arg1);
            break;
        case kSysNewfstatat: {
            const auto path = readGuestString(vm, args->arg1);
            result = path.has_value() ? writeNativeStat(*path, args->arg2) : negativeErrno(EFAULT);
            break;
        }
        case kSysLseek:
            result = handleLseek(static_cast<int>(args->arg0), static_cast<int64_t>(args->arg1), static_cast<int>(args->arg2));
            break;
        case kSysPread64:
            result = preadFromGuestFile(static_cast<int>(args->arg0), args->arg1,
                                        static_cast<size_t>(args->arg2), args->arg3);
            break;
        case kSysWritev:
            result = writeGuestOutputVector(static_cast<int>(args->arg0), args->arg1, args->arg2);
            break;
        case kSysMmap:
            result = handleMmap(args);
            break;
        case kSysMprotect:
            result = handleMprotect(args->arg0, args->arg1, args->arg2);
            break;
        case kSysMunmap:
            result = handleMunmap(args->arg0, args->arg1);
            break;
        case kSysMremap:
            result = negativeErrno(ENOSYS);
            break;
        case kSysMadvise:
            result = 0;
            break;
        case kSysBrk:
            result = handleBrk(args->arg0);
            break;
        case kSysAccess: {
            const auto path = readGuestString(vm, args->arg0);
            result = path.has_value() && guestPathExists(*path) ? 0 : negativeErrno(ENOENT);
            break;
        }
        case kSysReadlink: {
            const auto path = readGuestString(vm, args->arg0);
            result = path.has_value() ? handleReadlink(*path, args->arg1, args->arg2) : negativeErrno(EFAULT);
            break;
        }
        case kSysReadlinkat: {
            const auto path = readGuestString(vm, args->arg1);
            result = path.has_value() ? handleReadlink(*path, args->arg2, args->arg3) : negativeErrno(EFAULT);
            break;
        }
        case kSysFaccessat: {
            const auto path = readGuestString(vm, args->arg1);
            result = path.has_value() && guestPathExists(*path) ? 0 : negativeErrno(ENOENT);
            break;
        }
        case kSysGetcwd: {
            const std::string cwd = "/";
            if (args->arg1 < cwd.size() + 1) {
                result = negativeErrno(ERANGE);
            } else {
                result = writeGuestBytes(vm, args->arg0, cwd.c_str(), cwd.size() + 1)
                    ? static_cast<int64_t>(cwd.size() + 1)
                    : negativeErrno(EFAULT);
            }
            break;
        }
        case kSysClockGettime:
            result = handleClockGettime(args->arg1);
            break;
        case kSysGettimeofday:
            result = handleGettimeofday(args->arg0);
            break;
        case kSysUname:
            result = handleUname(args->arg0);
            break;
        case kSysPrlimit64:
            result = handlePrlimit64(args->arg3);
            break;
        case kSysArchPrctl:
            result = handleArchPrctl(args->arg0, args->arg1);
            break;
        case kSysSetTidAddress:
            result = kEmulatedPid;
            break;
        case kSysSetRobustList:
        case kSysRtSigaction:
        case kSysRtSigprocmask:
            result = 0;
            break;
        case kSysFutex:
            result = 0;
            break;
        case kSysFcntl:
            result = handleFcntl(static_cast<int>(args->arg0), args->arg1);
            break;
        case kSysGetpid:
            result = kEmulatedPid;
            break;
        case kSysGetuid:
        case kSysGeteuid:
            result = kEmulatedUid;
            break;
        case kSysGetgid:
        case kSysGetegid:
            result = kEmulatedGid;
            break;
        case kSysGetrandom: {
            std::vector<uint8_t> bytes(static_cast<size_t>(args->arg1));
            fillDeterministicRandom(bytes.data(), bytes.size());
            result = writeGuestBytes(vm, args->arg0, bytes.data(), bytes.size())
                ? static_cast<int64_t>(bytes.size())
                : negativeErrno(EFAULT);
            break;
        }
        case kSysRseq:
            result = negativeErrno(ENOSYS);
            break;
        case kSysIoctl:
            result = negativeErrno(ENOTTY);
            break;
        case kSysSocket:
        case kSysClone:
            result = negativeErrno(ENOSYS);
            break;
        case kSysExit:
            gProcess.exited = true;
            gProcess.exitCode = static_cast<int>(args->arg0 & 0xff);
            result = 0;
            break;
        case kSysExitGroup:
            gProcess.exited = true;
            gProcess.exitCode = static_cast<int>(args->arg0 & 0xff);
            result = 0;
            hookResult = -1;
            break;
        default:
            warnUnsupportedSyscallOnce(syscallNumber);
            result = negativeErrno(ENOSYS);
            break;
    }

    setSyscallReturn(vm, result);
    return hookResult;
}
