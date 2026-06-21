#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "icicle.h"

struct LinuxProcessImage {
    std::string path;
    std::string interpreterPath;

    uint64_t initialPc = 0;
    uint64_t programEntry = 0;
    uint64_t programHeaders = 0;
    uint64_t programHeaderEntrySize = 0;
    uint64_t programHeaderCount = 0;
    uint64_t interpreterBase = 0;
    uint64_t loadBias = 0;
    uint64_t brkStart = 0;
};

bool configureLinuxProcess(const LinuxProcessImage& image);
bool setupLinuxProcessStack(Icicle* vm);
void clearLinuxProcess();
bool linuxProcessActive();
bool linuxProcessExited();
int linuxProcessExitCode();
int handleLinuxProcessSyscall(void* data, uint64_t syscallNumber, const SyscallArgs* args);
