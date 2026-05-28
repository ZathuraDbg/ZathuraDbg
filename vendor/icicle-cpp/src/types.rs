// FFI callback type aliases, repr(C) structs, and enums shared across the crate.

use std::os::raw::{c_char, c_void, c_int};
use icicle_cpu::mem::perm;

pub type ViolationFunction = extern "C" fn(data: *mut c_void, address: u64, permission: u8, unmapped: c_int) -> c_int;
#[allow(dead_code)]
pub type RawFunction = extern "C" fn(data: *mut c_void);
pub type PtrFunction = extern "C" fn(data: *mut c_void, address: u64);
pub type SyscallHookFunction = extern "C" fn(data: *mut c_void, syscall_nr: u64, args: *const SyscallArgs) -> c_int;

// Define Memory Hook callback types matching ffi.h
pub type MemReadHookFunction = extern "C" fn(data: *mut c_void, address: u64, size: u8, value_read: *const u8);
pub type MemWriteHookFunction = extern "C" fn(data: *mut c_void, address: u64, size: u8, value_written: u64);

// Define debug instrumentation callback types
pub type LogWriteHookFunction = extern "C" fn(data: *mut c_void, name: *const c_char, address: u64, size: u8, value: u64);
pub type LogRegsHookFunction = extern "C" fn(data: *mut c_void, name: *const c_char, address: u64, num_regs: usize, reg_names: *const *const c_char, reg_values: *const u64);

// Define SyscallArgs struct matching ffi.h (must be repr(C))
#[repr(C)]
pub struct SyscallArgs {
    pub arg0: u64, // RDI
    pub arg1: u64, // RSI
    pub arg2: u64, // RDX
    pub arg3: u64, // R10
    pub arg4: u64, // R8
    pub arg5: u64, // R9
}

// Hook type identifiers for tracking different hook types
#[repr(C)]
#[allow(dead_code)]
pub enum HookType {
    Memory = 0,
    Execution = 1,
    Syscall = 2,
    Violation = 3,
}

// Coverage modes for instrumentation
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CoverageMode {
    Blocks = 0,
    Edges = 1,
    BlockCounts = 2,
    EdgeCounts = 3,
}

#[repr(C)]
pub struct RegInfo {
    pub name: *mut c_char,
    pub offset: u32,
    pub size: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MemoryProtection {
    NoAccess = 0,
    ReadOnly = 1,
    ReadWrite = 2,
    ExecuteOnly = 3,
    ExecuteRead = 4,
    ExecuteReadWrite = 5,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RunStatus {
    Running = 0,
    InstructionLimit = 1,
    Breakpoint = 2,
    Interrupted = 3,
    Halt = 4,
    Killed = 5,
    Deadlock = 6,
    OutOfMemory = 7,
    Unimplemented = 8,
    UnhandledException = 9,
}

/// Helper function to map MemoryProtection to underlying permission bits.
pub fn convert_protection(protection: MemoryProtection) -> u8 {
    match protection {
        MemoryProtection::NoAccess => perm::NONE,
        MemoryProtection::ReadOnly => perm::READ,
        MemoryProtection::ReadWrite => perm::READ | perm::WRITE,
        MemoryProtection::ExecuteOnly => perm::EXEC,
        MemoryProtection::ExecuteRead => perm::EXEC | perm::READ,
        MemoryProtection::ExecuteReadWrite => perm::EXEC | perm::READ | perm::WRITE,
    }
}

/// Helper to map underlying permission bits back to MemoryProtection.
pub fn perm_to_protection(perm_: u8) -> MemoryProtection {
    let read = (perm_ & perm::READ) != 0;
    let write = (perm_ & perm::WRITE) != 0;
    let exec = (perm_ & perm::EXEC) != 0;

    match (read, write, exec) {
        (true, true, true) => MemoryProtection::ExecuteReadWrite,
        (true, true, false) => MemoryProtection::ReadWrite,
        (true, false, true) => MemoryProtection::ExecuteRead,
        (true, false, false) => MemoryProtection::ReadOnly,
        (false, false, true) => MemoryProtection::ExecuteOnly,
        _ => MemoryProtection::NoAccess,
    }
}

#[repr(C)]
pub struct MemRegionInfo {
    pub address: u64,
    pub size: u64,
    pub protection: MemoryProtection,
}
