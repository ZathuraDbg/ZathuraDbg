use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uchar, c_void};
use std::ptr;
use std::fs::File;
use std::io::{Read, Write};
use icicle_cpu::mem::{Mapping, perm, Mmu, ReadAfterHook, WriteHook, MemoryMapping};
use icicle_cpu::{Cpu, ValueSource, VmExit, ExceptionCode, Regs, ShadowStack, Exception};
use icicle_vm::cpu::{Environment, debug_info::{DebugInfo, SourceLocation}};
use icicle_vm::cpu::mem::AllocLayout;
use target_lexicon::Architecture;
use sleigh_runtime::NamedRegister;
use serde::{Serialize, Deserialize};
// We need to add bincode for serialization
extern crate bincode;

// Import log for logging
extern crate tracing;

pub type ViolationFunction = extern "C" fn(data: *mut c_void, address: u64, permission: u8, unmapped: c_int) -> c_int;
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
pub enum HookType {
    Memory = 0,
    Execution = 1,
    Syscall = 2,
    Violation = 3,
}

// Coverage modes for instrumentation (matching the icicle_fuzzing::CoverageMode enum)
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CoverageMode {
    Blocks = 0,      // Store a bit whenever a block is hit
    Edges = 1,       // Store a bit whenever an edge is hit
    BlockCounts = 2, // Increment a counter whenever a block is hit
    EdgeCounts = 3,  // Increment a counter whenever an edge is hit
}

/// Adds a hook for memory access violations (read/write/execute violations and unmapped memory)
/// 
/// When a memory violation occurs, the callback is invoked with:
/// - data: User-provided context pointer
/// - address: The address that caused the violation
/// - permission: The permission that was violated (read/write/execute)
/// - unmapped: 1 if the memory was unmapped, 0 if it was a permission violation
/// 
/// If the callback returns non-zero, the violation will be ignored and execution continues.
/// If the callback returns zero, the emulator will stop with an exception.
///
/// Returns a hook ID on success, 0 on failure.
#[no_mangle]
pub extern "C" fn icicle_add_violation_hook(
    vm_ptr: *mut Icicle,
    callback: ViolationFunction,
    data: *mut c_void,
) -> u32 {
    if vm_ptr.is_null() {
        return 0;
    }
    let vm = unsafe { &mut *vm_ptr };

    // Store the callback in the VM's custom data for when we handle exceptions
    vm.violation_callback = Some((callback, data));

    // Return a fixed ID for the violation hook type
    1
}

/// Adds a hook for syscall interception
/// 
/// When a syscall is executed, the callback is invoked with:
/// - data: User-provided context pointer
/// - syscall_nr: The syscall number
/// - args: Pointer to the syscall arguments
///
/// Returns hook ID 2 on success, 0 on failure.
#[no_mangle]
pub extern "C" fn icicle_add_syscall_hook(
    vm_ptr: *mut Icicle,
    callback: SyscallHookFunction,
    data: *mut c_void,
) -> u32 {
    if vm_ptr.is_null() {
        return 0;
    }
    let vm = unsafe { &mut *vm_ptr };
    vm.syscall_callback = Some((callback, data));
    2
}

/// Adds a hook for code execution (basic block hook)
/// 
/// The callback is invoked before each basic block is executed with:
/// - data: User-provided context pointer
/// - address: The address of the basic block about to be executed
///
/// Returns a unique FFI hook ID (>= 3) on success, 0 on failure.
#[no_mangle]
pub extern "C" fn icicle_add_execution_hook(
    vm_ptr: *mut Icicle,
    callback: PtrFunction,
    data: *mut c_void,
) -> u32 {
    if vm_ptr.is_null() {
        return 0;
    }
    let vm = unsafe { &mut *vm_ptr };

    // Create the hook handler that calls the C callback
    let hook_fn = Box::new(move |_cpu: &mut Cpu, pc: u64| {
        (callback)(data, pc);
    });

    // Add the hook to the core VM and get its internal ID
    let internal_id = vm.vm.cpu.add_hook(hook_fn.clone()); // Clone needed for storage
    
    // Register the injector to activate the hook for all basic blocks
    icicle_vm::injector::register_block_hook_injector(&mut vm.vm, 0, u64::MAX, internal_id);

    // Generate and store the FFI-level hook
    let ffi_hook_id = vm.next_execution_hook_id;
    vm.execution_hooks.insert(ffi_hook_id, hook_fn);
    vm.next_execution_hook_id += 1;

    ffi_hook_id
}

/// Removes a previously registered execution hook using its FFI ID.
/// Note: Due to limitations in the core library, this only removes the hook
/// from FFI tracking; the underlying VM hook might still exist but become inactive
/// if the associated data/callback is dropped.
#[no_mangle]
pub extern "C" fn icicle_remove_execution_hook(
    vm_ptr: *mut Icicle,
    hook_id: u32,
) -> c_int {
    if vm_ptr.is_null() {
        return -1;
    }
    let vm = unsafe { &mut *vm_ptr };

    // Check if the hook exists in our tracking (IDs >= 3)
    if hook_id < 3 || !vm.execution_hooks.contains_key(&hook_id) {
        return -1;
    }

    // Remove the hook from our tracking map.
    // The actual hook closure will be dropped when removed from the map.
    // We cannot remove it from the core VM's hook list.
    vm.execution_hooks.remove(&hook_id);
    // Maybe clear TLB? Unsure if needed for execution hooks.
    // vm.vm.cpu.mem.tlb.clear(); 

    0 // Return success
}

/// Removes a previously registered hook (Violation or Syscall ONLY)
/// Use type-specific removal functions (e.g., icicle_remove_execution_hook) for other types.
#[no_mangle]
pub extern "C" fn icicle_remove_hook(
    vm_ptr: *mut Icicle,
    hook_id: u32
) -> c_int {
    if vm_ptr.is_null() {
        return -1;
    }
    let vm = unsafe { &mut *vm_ptr };
    let mut removed = false;

    if hook_id == 1 { // Violation hook (Managed internally)
        if vm.violation_callback.is_some() {
            vm.violation_callback = None;
            removed = true;
        }
    } else if hook_id == 2 { // Syscall hook (Managed internally)
        if vm.syscall_callback.is_some() {
            vm.syscall_callback = None;
            removed = true;
        }
    } else {
        // This function only handles Violation (1) and Syscall (2) hooks.
        removed = false;
    }

    if removed {
        0 // Return success
    } else {
        // Return error (hook not found, already removed, or not supported for removal)
        -1
    }
}

/// Legacy function to maintain compatibility with existing code
#[no_mangle]
pub extern "C" fn icicle_remove_syscall_hook(vm_ptr: *mut Icicle, hook_id: u32) -> c_int {
    icicle_remove_hook(vm_ptr, hook_id)
}

#[repr(C)]
pub struct RegInfo {
    pub name: *mut c_char, // allocated C string (to be freed by caller)
    pub offset: u32,
    pub size: u8,
}

// ----- Helper for x86 flags handling -----
struct X86FlagsRegHandler {
    pub eflags: pcode::VarNode,
}

pub struct RawEnvironment {
    debug_info: DebugInfo,
}

impl RawEnvironment {
    pub fn new() -> Self {
        Self { debug_info: DebugInfo::default() }
    }
}

impl icicle_cpu::RegHandler for X86FlagsRegHandler {
    fn read(&mut self, cpu: &mut Cpu) {
        let eflags = icicle_vm::x86::eflags(cpu);
        cpu.write_var::<u32>(self.eflags, eflags);
    }

    fn write(&mut self, cpu: &mut Cpu) {
        let eflags = cpu.read_var::<u32>(self.eflags);
        icicle_vm::x86::set_eflags(cpu, eflags);
    }
}

// ----- C-friendly enums -----

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

/// Helper function to map our MemoryProtection to the underlying permission bits.
fn convert_protection(protection: MemoryProtection) -> u8 {
    match protection {
        MemoryProtection::NoAccess => perm::NONE,
        MemoryProtection::ReadOnly => perm::READ,
        MemoryProtection::ReadWrite => perm::READ | perm::WRITE,
        MemoryProtection::ExecuteOnly => perm::EXEC,
        MemoryProtection::ExecuteRead => perm::EXEC | perm::READ,
        MemoryProtection::ExecuteReadWrite => perm::EXEC | perm::READ | perm::WRITE,
    }
}

// ----- The Icicle VM structure -----
// This structure is treated as opaque in the FFI API.
pub struct Icicle {
    architecture: String,
    vm: icicle_vm::Vm,
    regs: HashMap<String, NamedRegister>,
    violation_callback: Option<(ViolationFunction, *mut c_void)>,
    syscall_callback: Option<(SyscallHookFunction, *mut c_void)>,
    // Track memory hooks
    mem_read_hooks: HashMap<u32, Box<dyn ReadAfterHook>>,
    mem_write_hooks: HashMap<u32, Box<dyn WriteHook>>,
    next_mem_hook_id: u32,
    // Track execution hooks
    execution_hooks: HashMap<u32, Box<dyn FnMut(&mut Cpu, u64)>>,
    next_execution_hook_id: u32,
    // Coverage instrumentation
    coverage_mode: CoverageMode,
    coverage_start_addr: u64,
    coverage_end_addr: u64,
    context_bits: u8,
    compcov_level: u8,
    instrumentation_enabled: bool,
    coverage_map: Vec<u8>,
    coverage_hook_id: Option<u32>,
}

impl Icicle {
    /// Create a new Icicle instance.
    pub fn new(
        architecture: &str,
        jit: bool,
        jit_mem: bool,
        shadow_stack: bool,
        recompilation: bool,
        track_uninitialized: bool,
        optimize_instructions: bool,
        optimize_block: bool,
        tracing: bool,
    ) -> Result<Self, String> {
        // Prevent mixing '_' and '-'
        if architecture.split('-').count() != 1 {
            return Err(format!("Bad architecture format: {}", architecture));
        }

        if tracing {
            let _ = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_target(false)
                .try_init();
        }

        let mut config = icicle_vm::cpu::Config::from_target_triple(
            format!("{}-none", architecture).as_str(),
        );
        if config.triple.architecture == target_lexicon::Architecture::Unknown {
            return Err(format!("Unknown architecture: {}", architecture));
        }

        config.enable_jit = jit;
        config.enable_jit_mem = jit_mem;
        config.enable_shadow_stack = shadow_stack;
        config.enable_recompilation = recompilation;
        config.track_uninitialized = track_uninitialized;
        config.optimize_instructions = optimize_instructions;
        config.optimize_block = optimize_block;

        let mut vm = icicle_vm::build(&config)
            .map_err(|e| format!("VM build error: {}", e))?;

        let mut regs = HashMap::new();
        let sleigh = &vm.cpu.arch.sleigh;
        for reg in &sleigh.named_registers {
            let name = sleigh.get_str(reg.name);
            regs.insert(name.to_lowercase(), reg.clone());
        }

        // Special handling for x86 flags
        match config.triple.architecture {
            Architecture::X86_32(_) | Architecture::X86_64 | Architecture::X86_64h => {
                let eflags = sleigh.get_reg("eflags").unwrap().var;
                let reg_handler = X86FlagsRegHandler { eflags };
                vm.cpu.add_reg_handler(eflags.id, Box::new(reg_handler));
            }
            _ => {}
        }

        Ok(Icicle {
            architecture: architecture.to_string(),
            vm,
            regs,
            violation_callback: None,
            syscall_callback: None,
            mem_read_hooks: HashMap::new(),
            mem_write_hooks: HashMap::new(),
            next_mem_hook_id: 0, // Start memory IDs at 0
            execution_hooks: HashMap::new(),
            next_execution_hook_id: 3, // Start execution IDs after Violation(1) and Syscall(2)
            coverage_mode: CoverageMode::Blocks,
            coverage_start_addr: 0,
            coverage_end_addr: 0,
            context_bits: 0,
            compcov_level: 0,
            instrumentation_enabled: true,
            coverage_map: vec![0; 4096],
            coverage_hook_id: None,
        })
    }

    // Methods for icicle functions follow:
    pub fn get_icount_limit(&self) -> u64 {
        self.vm.icount_limit
    }

    pub fn set_icount_limit(&mut self, value: u64) {
        self.vm.icount_limit = value;
    }

    pub fn get_icount(&self) -> u64 {
        self.vm.cpu.icount
    }

    pub fn set_icount(&mut self, value: u64) {
        self.vm.cpu.icount = value;
    }

    pub fn get_pc(&self) -> u64 {
        self.vm.cpu.read_pc()
    }

    pub fn set_pc(&mut self, address: u64) {
        self.vm.cpu.write_pc(address)
    }

    pub fn get_sp(&mut self) -> u64 {
        self.vm.cpu.read_reg(self.vm.cpu.arch.reg_sp)
    }

    pub fn set_sp(&mut self, address: u64) {
        self.vm.cpu.write_reg(self.vm.cpu.arch.reg_sp, address)
    }

    pub fn get_mem_capacity(&self) -> usize {
        self.vm.cpu.mem.capacity()
    }

    pub fn set_mem_capacity(&mut self, capacity: usize) -> Result<(), String> {
        if self.vm.cpu.mem.set_capacity(capacity) {
            Ok(())
        } else {
            Err("Reducing memory capacity is not supported".to_string())
        }
    }

    pub fn mem_map(&mut self, address: u64, size: u64, protection: MemoryProtection) -> Result<(), String> {
        let init_perm = if self.vm.cpu.mem.track_uninitialized { perm::NONE } else { perm::INIT };
        let mapping = Mapping {
            perm: convert_protection(protection) | init_perm,
            value: 0,
        };
        if self.vm.cpu.mem.map_memory_len(address, size, mapping) {
            Ok(())
        } else {
            Err(format!("Failed to map memory {:#X}[{:#X}]", address, size))
        }
    }

    pub fn mem_unmap(&mut self, address: u64, size: u64) -> Result<(), String> {
        if self.vm.cpu.mem.unmap_memory_len(address, size) {
            Ok(())
        } else {
            Err(format!("Failed to unmap memory {:#X}[{:#X}]", address, size))
        }
    }

    pub fn mem_protect(&mut self, address: u64, size: usize, protection: MemoryProtection) -> Result<(), String> {
        self.vm.cpu.mem.update_perm(address, size as u64, convert_protection(protection))
            .map_err(|e| format!("Failed to protect memory {:#X}[{:#X}]: {:?}", address, size, e))?;
        Ok(())
    }

    /// Reads memory into a newly allocated Vec.
    pub fn mem_read(&mut self, address: u64, size: usize) -> Result<Vec<u8>, String> {
        let mut buffer = vec![0u8; size];
        self.vm.cpu.mem.read_bytes(address, &mut buffer[..], perm::NONE)
            .map_err(|e| format!("Failed to read memory {:#X}[{:#X}]: {:?}", address, size, e))?;
        Ok(buffer)
    }

    pub fn mem_write(&mut self, address: u64, data: &[u8]) -> Result<(), String> {
        let size = data.len();
        self.vm.cpu.mem.write_bytes(address, data, perm::NONE)
            .map_err(|e| format!("Failed to write memory {:#X}[{:#X}]: {:?}", address, size, e))
    }

    pub fn reset(&mut self) {
        self.vm.reset();
    }

    pub fn run(&mut self) -> RunStatus {
        let original_exit = self.vm.run();

        match original_exit {
            VmExit::UnhandledException(_) => {
                let cpu = &mut self.vm.cpu;
                let exception_code_val = cpu.exception.code;
                let exception_value = cpu.exception.value;
                
                let is_syscall = exception_code_val == ExceptionCode::Syscall as u32;
                let is_violation = !is_syscall && (
                       exception_code_val == ExceptionCode::ReadUnmapped as u32 ||
                       exception_code_val == ExceptionCode::WriteUnmapped as u32 ||
                       exception_code_val == ExceptionCode::ReadPerm as u32 ||
                       exception_code_val == ExceptionCode::WritePerm as u32 ||
                       exception_code_val == ExceptionCode::ExecViolation as u32);

                if is_violation && self.violation_callback.is_some() {
                    let (callback, data) = self.violation_callback.as_ref().unwrap(); 
                    let address = exception_value;
                    let unmapped = if exception_code_val == ExceptionCode::ReadUnmapped as u32 ||
                                     exception_code_val == ExceptionCode::WriteUnmapped as u32 { 1 } else { 0 };
                    let permission = match exception_code_val { 
                         code if code == ExceptionCode::ReadPerm as u32 || code == ExceptionCode::ReadUnmapped as u32 => perm::READ,
                         code if code == ExceptionCode::WritePerm as u32 || code == ExceptionCode::WriteUnmapped as u32 => perm::WRITE,
                         code if code == ExceptionCode::ExecViolation as u32 => perm::EXEC,
                         _ => 0 };
                    
                    let result = (callback)(*data, address, permission, unmapped);
                    
                    if result != 0 { 
                        if address == 0 && (exception_code_val == ExceptionCode::WriteUnmapped as u32 ||
                                            exception_code_val == ExceptionCode::WritePerm as u32) {
                            let pc = cpu.read_pc(); 
                            cpu.write_pc(pc + 6);    
                        }
                        cpu.exception.clear(); 
                        return self.run(); 
                    } else {
                        return RunStatus::UnhandledException;
                    }

                } else if is_syscall && self.syscall_callback.is_some() {
                    let (callback, data) = self.syscall_callback.as_ref().unwrap(); 
                    
                    let syscall_nr = match cpu.arch.sleigh.get_reg("RAX") {
                        Some(reg) => cpu.read_reg(reg.var),
                        None => u64::MAX, 
                    };
                    let args = SyscallArgs {
                        arg0: match cpu.arch.sleigh.get_reg("RDI") { Some(r) => cpu.read_reg(r.var), None => 0 },
                        arg1: match cpu.arch.sleigh.get_reg("RSI") { Some(r) => cpu.read_reg(r.var), None => 0 },
                        arg2: match cpu.arch.sleigh.get_reg("RDX") { Some(r) => cpu.read_reg(r.var), None => 0 },
                        arg3: match cpu.arch.sleigh.get_reg("R10") { Some(r) => cpu.read_reg(r.var), None => 0 },
                        arg4: match cpu.arch.sleigh.get_reg("R8")  { Some(r) => cpu.read_reg(r.var), None => 0 },
                        arg5: match cpu.arch.sleigh.get_reg("R9")  { Some(r) => cpu.read_reg(r.var), None => 0 },
                    };
                    
                    let callback_result = (callback)(*data, syscall_nr, &args as *const SyscallArgs);

                    match callback_result {
                        0 => { 
                            if syscall_nr == 0x3C { // sys_exit
                                cpu.exception.clear();
                                return RunStatus::Halt;
                            } else {
                                let pc = cpu.read_pc();
                                cpu.write_pc(pc + 2); 
                                cpu.exception.clear();
                                return self.run(); 
                            }
                        }
                        1 => { 
                            let pc = cpu.read_pc();
                            cpu.write_pc(pc + 2); 
                            cpu.exception.clear();
                            return self.run(); 
                        }
                        _ => { 
                            return RunStatus::UnhandledException;
                        }
                    }
                } else {
                    return RunStatus::UnhandledException;
                }
            }
            // Map other VmExit types
            VmExit::Running => RunStatus::Running,
            VmExit::InstructionLimit => RunStatus::InstructionLimit,
            VmExit::Breakpoint => RunStatus::Breakpoint,
            VmExit::Interrupted => RunStatus::Interrupted,
            VmExit::Halt => RunStatus::Halt,
            VmExit::Killed => RunStatus::Killed,
            VmExit::Deadlock => RunStatus::Deadlock,
            VmExit::OutOfMemory => RunStatus::OutOfMemory,
            VmExit::Unimplemented => RunStatus::Unimplemented,
        }
    }

    pub fn run_until(&mut self, address: u64) -> RunStatus {
        let breakpoint_added = self.vm.add_breakpoint(address);
        let status = self.run();
        if breakpoint_added {
            self.vm.remove_breakpoint(address);
        }
        status
    }

    pub fn step(&mut self, count: u64) -> RunStatus {
        let old_limit = self.vm.icount_limit;
        self.vm.icount_limit = self.vm.cpu.icount.saturating_add(count);
        let status = self.run();
        self.vm.icount_limit = old_limit;
        status
    }

    pub fn add_breakpoint(&mut self, address: u64) -> bool {
        self.vm.add_breakpoint(address)
    }

    pub fn remove_breakpoint(&mut self, address: u64) -> bool {
        self.vm.remove_breakpoint(address)
    }

    pub fn get_backtrace(&mut self, max_frames: usize) -> String {
        icicle_vm::debug::backtrace_with_limit(&mut self.vm, max_frames)
    }

    pub fn dump_disasm(&self) -> Result<String, String> {
        icicle_vm::debug::dump_disasm(&self.vm)
            .map_err(|e| format!("Failed to dump disassembly: {}", e))
    }

    pub fn current_disasm(&self) -> String {
        icicle_vm::debug::current_disasm(&self.vm)
    }

    /// Steps backward in execution by the specified number of instructions.
    /// Returns None if there are no snapshots to step back to.
    pub fn step_back(&mut self, count: u64) -> Option<RunStatus> {
        // Map VmExit to RunStatus if step_back succeeds
        self.vm.step_back(count).map(|exit| match exit {
            VmExit::Running => RunStatus::Running,
            VmExit::InstructionLimit => RunStatus::InstructionLimit,
            VmExit::Breakpoint => RunStatus::Breakpoint,
            VmExit::Interrupted => RunStatus::Interrupted,
            VmExit::Halt => RunStatus::Halt,
            VmExit::Killed => RunStatus::Killed,
            VmExit::Deadlock => RunStatus::Deadlock,
            VmExit::OutOfMemory => RunStatus::OutOfMemory,
            VmExit::Unimplemented => RunStatus::Unimplemented,
            VmExit::UnhandledException(_) => RunStatus::UnhandledException,
        })
    }

    /// Goes to a specific instruction count if snapshots are available.
    /// Returns None if there are no snapshots that can reach the specified instruction count.
    pub fn goto_icount(&mut self, target_icount: u64) -> Option<RunStatus> {
        // Map VmExit to RunStatus if goto_icount succeeds
        self.vm.goto_icount(target_icount).map(|exit| match exit {
            VmExit::Running => RunStatus::Running,
            VmExit::InstructionLimit => RunStatus::InstructionLimit,
            VmExit::Breakpoint => RunStatus::Breakpoint,
            VmExit::Interrupted => RunStatus::Interrupted,
            VmExit::Halt => RunStatus::Halt,
            VmExit::Killed => RunStatus::Killed,
            VmExit::Deadlock => RunStatus::Deadlock,
            VmExit::OutOfMemory => RunStatus::OutOfMemory,
            VmExit::Unimplemented => RunStatus::Unimplemented,
            VmExit::UnhandledException(_) => RunStatus::UnhandledException,
        })
    }

    /// Saves a snapshot at the current execution state.
    /// Snapshots are required for step_back and goto_icount functionality.
    pub fn save_snapshot(&mut self) {
        self.vm.save_snapshot();
    }
}

fn reg_find<'a>(i: &'a Icicle, name: &str) -> Result<&'a NamedRegister, String> {
    let sleigh = &i.vm.cpu.arch.sleigh;
    match sleigh.get_reg(name) {
        None => {
            i.regs.get(&name.to_lowercase())
                .ok_or(format!("Register not found: {}", name))
        }
        Some(r) => Ok(r),
    }
}

#[no_mangle]
pub extern "C" fn icicle_new(
    architecture: *const c_char,
    jit: bool,
    jit_mem: bool,
    shadow_stack: bool,
    recompilation: bool,
    track_uninitialized: bool,
    optimize_instructions: bool,
    optimize_block: bool,
    tracing: bool,
) -> *mut Icicle {
    if architecture.is_null() {
        return std::ptr::null_mut();
    }
    let c_str = unsafe { CStr::from_ptr(architecture) };
    let arch_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    match Icicle::new(
        arch_str,
        jit,
        jit_mem,
        shadow_stack,
        recompilation,
        track_uninitialized,
        optimize_instructions,
        optimize_block,
        tracing,
    ) {
        Ok(vm) => Box::into_raw(Box::new(vm)),
        Err(err) => {
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn icicle_free(ptr: *mut Icicle) {
    if !ptr.is_null() {
        unsafe { Box::from_raw(ptr); }
    }
}

#[no_mangle]
pub extern "C" fn icicle_get_icount(ptr: *const Icicle) -> u64 {
    if ptr.is_null() {
        return 0;
    }
    unsafe { (*ptr).get_icount() }
}

#[no_mangle]
pub extern "C" fn icicle_set_icount(ptr: *mut Icicle, count: u64) {
    if ptr.is_null() {
        return;
    }
    unsafe { (*ptr).set_icount(count); }
}

#[no_mangle]
pub extern "C" fn icicle_get_pc(ptr: *const Icicle) -> u64 {
    if ptr.is_null() {
        return 0;
    }
    unsafe { (*ptr).get_pc() }
}

#[no_mangle]
pub extern "C" fn icicle_set_pc(ptr: *mut Icicle, addr: u64) {
    if ptr.is_null() {
        return;
    }
    unsafe { (*ptr).set_pc(addr); }
}

#[no_mangle]
pub extern "C" fn icicle_reset(ptr: *mut Icicle) {
    if ptr.is_null() {
        return;
    }
    unsafe { (*ptr).reset(); }
}

#[no_mangle]
pub extern "C" fn icicle_run(ptr: *mut Icicle) -> RunStatus {
    if ptr.is_null() {
        return RunStatus::UnhandledException;
    }
    unsafe { (*ptr).run() }
}

#[no_mangle]
pub extern "C" fn icicle_step(ptr: *mut Icicle, count: u64) -> RunStatus {
    if ptr.is_null() {
        return RunStatus::UnhandledException;
    }
    unsafe { (*ptr).step(count) }
}

#[no_mangle]
pub extern "C" fn icicle_mem_map(ptr: *mut Icicle, address: u64, size: u64, protection: MemoryProtection) -> c_int {
    if ptr.is_null() {
        return -1;
    }
    let res = unsafe { (*ptr).mem_map(address, size, protection) };
    match res {
        Ok(_) => 0,
        Err(err) => {
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn icicle_mem_unmap(ptr: *mut Icicle, address: u64, size: u64) -> c_int {
    if ptr.is_null() {
        return -1;
    }
    let res = unsafe { (*ptr).mem_unmap(address, size) };
    match res {
        Ok(_) => 0,
        Err(err) => {
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn icicle_mem_protect(ptr: *mut Icicle, address: u64, size: usize, protection: MemoryProtection) -> c_int {
    if ptr.is_null() {
        return -1;
    }
    let res = unsafe { (*ptr).mem_protect(address, size, protection) };
    match res {
        Ok(_) => 0,
        Err(err) => {
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn icicle_mem_read(ptr: *mut Icicle, address: u64, size: usize, out_size: *mut usize) -> *mut c_uchar {
    if ptr.is_null() || out_size.is_null() {
        return std::ptr::null_mut();
    }
    let res = unsafe { (*ptr).mem_read(address, size) };
    match res {
        Ok(buffer) => {
            let len = buffer.len();
            unsafe { *out_size = len; }
            let mut buf = buffer.into_boxed_slice();
            let ptr = buf.as_mut_ptr();
            std::mem::forget(buf);
            ptr
        }
        Err(err) => {
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn icicle_mem_write(ptr: *mut Icicle, address: u64, data: *const c_uchar, size: usize) -> c_int {
    if ptr.is_null() || data.is_null() {
        return -1;
    }
    let slice = unsafe { std::slice::from_raw_parts(data, size) };
    let res = unsafe { (*ptr).mem_write(address, slice) };
    match res {
        Ok(_) => 0,
        Err(err) => {
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn icicle_free_buffer(buffer: *mut c_uchar, size: usize) {
    if buffer.is_null() {
        return;
    }
    unsafe {
        let _ = Box::from_raw(std::slice::from_raw_parts_mut(buffer, size));
    }
}

#[no_mangle]
pub extern "C" fn icicle_reg_read(vm_ptr: *mut Icicle, reg_name: *const c_char, out_value: *mut u64) -> c_int {
    if vm_ptr.is_null() || reg_name.is_null() || out_value.is_null() {
        return -1;
    }
    let vm = unsafe { &mut *vm_ptr };
    let c_str = unsafe { CStr::from_ptr(reg_name) };
    let name = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    match reg_find(vm, name) {
        Ok(reg) => {
            let value = vm.vm.cpu.read_reg(reg.var);
            unsafe { *out_value = value; }
            0
        }
        Err(err) => {
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn icicle_reg_write(vm_ptr: *mut Icicle, reg_name: *const c_char, value: u64) -> c_int {
    if vm_ptr.is_null() || reg_name.is_null() {
        return -1;
    }
    let vm = unsafe { &mut *vm_ptr };
    let c_str = unsafe { CStr::from_ptr(reg_name) };
    let name = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    match reg_find(vm, name) {
        Ok(reg) => {
            if reg.var == vm.vm.cpu.arch.reg_pc {
                vm.vm.cpu.write_pc(value);
            } else {
                vm.vm.cpu.write_reg(reg.var, value);
            }
            0
        }
        Err(err) => {
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn icicle_get_sp(ptr: *mut Icicle) -> u64 {
    if ptr.is_null() {
        return 0;
    }
    unsafe { (*ptr).get_sp() }
}

#[no_mangle]
pub extern "C" fn icicle_set_sp(ptr: *mut Icicle, addr: u64) {
    if ptr.is_null() {
        return;
    }
    unsafe { (*ptr).set_sp(addr); }
}

#[no_mangle]
pub extern "C" fn icicle_reg_list(vm_ptr: *mut Icicle, out_count: *mut usize) -> *mut RegInfo {
    if vm_ptr.is_null() || out_count.is_null() {
        return ptr::null_mut();
    }
    let vm = unsafe { &*vm_ptr };
    let sleigh = &vm.vm.cpu.arch.sleigh;
    let mut regs_vec: Vec<RegInfo> = Vec::new();
    for reg in &sleigh.named_registers {
        let name = sleigh.get_str(reg.name);
        let cstring = match CString::new(name) {
            Ok(s) => s,
            Err(_) => continue,
        };
        regs_vec.push(RegInfo {
            name: cstring.into_raw(),
            offset: reg.offset,
            size: reg.var.size,
        });
    }
    unsafe {
        *out_count = regs_vec.len();
    }
    let boxed_slice = regs_vec.into_boxed_slice();
    Box::into_raw(boxed_slice) as *mut RegInfo
}

#[no_mangle]
pub extern "C" fn icicle_reg_list_free(regs: *mut RegInfo, count: usize) {
    if regs.is_null() {
        return;
    }
    unsafe {
        let slice = std::slice::from_raw_parts_mut(regs, count);
        for reg in &mut *slice {
            if !reg.name.is_null() {
                let _ = CString::from_raw(reg.name);
            }
        }
        let _ = Box::from_raw(slice as *mut [RegInfo]);
    }
}

#[no_mangle]
pub extern "C" fn icicle_reg_size(vm_ptr: *mut Icicle, reg_name: *const c_char) -> c_int {
    if vm_ptr.is_null() || reg_name.is_null() {
        return -1;
    }
    let vm = unsafe { &*vm_ptr };
    let c_str = unsafe { CStr::from_ptr(reg_name) };
    let name = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    match reg_find(vm, name) {
        Ok(reg) => reg.var.size as c_int,
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn icicle_get_mem_capacity(ptr: *mut Icicle) -> usize {
    if ptr.is_null() {
        return 0;
    }
    unsafe { (*ptr).get_mem_capacity() }
}

#[no_mangle]
pub extern "C" fn icicle_set_mem_capacity(ptr: *mut Icicle, capacity: usize) -> c_int {
    if ptr.is_null() {
        return -1;
    }
    let vm = unsafe { &mut *ptr };
    let current_capacity = vm.get_mem_capacity();
    
    if capacity < current_capacity {
        return -1;
    }

    match vm.set_mem_capacity(capacity) {
        Ok(()) => 0,
        Err(err) => {
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn icicle_add_breakpoint(ptr: *mut Icicle, address: u64) -> c_int {
    if ptr.is_null() {
        return 0;
    }
    let added = unsafe { (*ptr).add_breakpoint(address) };
    if added { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn icicle_remove_breakpoint(ptr: *mut Icicle, address: u64) -> c_int {
    if ptr.is_null() {
        return 0;
    }
    let removed = unsafe { (*ptr).remove_breakpoint(address) };
    if removed { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn icicle_run_until(ptr: *mut Icicle, address: u64) -> RunStatus {
    if ptr.is_null() {
        return RunStatus::UnhandledException;
    }
    unsafe { (*ptr).run_until(address) }
}

#[no_mangle]
pub extern "C" fn icicle_get_exception_code(ptr: *const Icicle) -> u32 {
    if ptr.is_null() {
        return 0;
    }
    let vm = unsafe { &*ptr };
    
    // Get the exception code from the CPU
    let raw_code = vm.vm.cpu.exception.code;
    
    // Convert the internal exception code to the C API's IcicleExceptionCode
    // We need to map the internal hex values to the sequential values expected by the C API
    match raw_code {
        0x0000 => 0,  // Exception_NoException
        0x0001 => 1,  // Exception_InstructionLimit
        0x0002 => 2,  // Exception_Halt
        0x0003 => 3,  // Exception_Sleep
        0x0101 => 4,  // Exception_Syscall
        0x0102 => 5,  // Exception_CpuStateChanged
        0x0103 => 6,  // Exception_DivisionException
        0x0201 => 7,  // Exception_ReadUnmapped
        0x0202 => 8,  // Exception_ReadPerm
        0x0203 => 9,  // Exception_ReadUnaligned
        0x0204 => 10, // Exception_ReadWatch
        0x0205 => 11, // Exception_ReadUninitialized
        0x0301 => 12, // Exception_WriteUnmapped
        0x0302 => 13, // Exception_WritePerm
        0x0303 => 14, // Exception_WriteWatch
        0x0304 => 15, // Exception_WriteUnaligned
        0x0401 => 16, // Exception_ExecViolation
        0x0402 => 17, // Exception_SelfModifyingCode
        0x0501 => 18, // Exception_OutOfMemory
        0x0502 => 19, // Exception_AddressOverflow
        0x1001 => 20, // Exception_InvalidInstruction
        0x1002 => 21, // Exception_UnknownInterrupt
        0x1003 => 22, // Exception_UnknownCpuID
        0x1004 => 23, // Exception_InvalidOpSize
        0x1005 => 24, // Exception_InvalidFloatSize
        0x1006 => 25, // Exception_CodeNotTranslated
        0x1007 => 26, // Exception_ShadowStackOverflow
        0x1008 => 27, // Exception_ShadowStackInvalid
        0x1009 => 28, // Exception_InvalidTarget
        0x100a => 29, // Exception_UnimplementedOp
        0x2001 => 30, // Exception_ExternalAddr
        0x2002 => 31, // Exception_Environment
        0x3001 => 32, // Exception_JitError
        0x3002 => 33, // Exception_InternalError
        0x3003 => 34, // Exception_UnmappedRegister
        _ => 35,      // Exception_UnknownError
    }
}

impl Environment for RawEnvironment {
    fn load(&mut self, cpu: &mut Cpu, code_bytes: &[u8]) -> Result<(), String> {
        let layout = AllocLayout { addr: Some(0x10000), size: 0x1000, align: 0x1000 };

        let base_addr = cpu
            .mem
            .alloc_memory(layout, Mapping { perm: perm::MAP, value: 0xaa })
            .map_err(|e| format!("Failed to allocate memory: {e:?}"))?;

        cpu.mem.update_perm(layout.addr.unwrap(), layout.size, perm::EXEC | perm::READ)
            .map_err(|e| format!("Failed to update perm: {e:?}"))?;

        cpu.mem.write_bytes(base_addr, code_bytes, perm::NONE)
            .map_err(|e| format!("Failed to write memory: {e:?}"))?;

        (cpu.arch.on_boot)(cpu, base_addr);

        Ok(())
    }

    fn handle_exception(&mut self, _: &mut Cpu) -> Option<VmExit> { None }

    fn symbolize_addr(&mut self, _: &mut Cpu, addr: u64) -> Option<SourceLocation> {
        self.debug_info.symbolize_addr(addr)
    }

    fn lookup_symbol(&mut self, symbol: &str) -> Option<u64> {
        self.debug_info.symbols.resolve_sym(symbol)
    }

    fn snapshot(&mut self) -> Box<dyn std::any::Any> {
        Box::new(())
    }

    fn restore(&mut self, _: &Box<dyn std::any::Any>) {}
}

#[no_mangle]
pub extern "C" fn icicle_rawenv_new() -> *mut RawEnvironment {
    Box::into_raw(Box::new(RawEnvironment::new()))
}

#[no_mangle]
pub extern "C" fn icicle_rawenv_free(env: *mut RawEnvironment) {
    if !env.is_null() {
        unsafe { Box::from_raw(env); }
    }
}

#[no_mangle]
pub extern "C" fn icicle_rawenv_load(
    env: *mut RawEnvironment,
    cpu: *mut std::os::raw::c_void,
    code: *const c_uchar,
    size: usize,
) -> c_int {
    if env.is_null() || cpu.is_null() || code.is_null() {
        return -1;
    }
    let cpu = unsafe { &mut *(cpu as *mut Cpu) };
    let code_slice = unsafe { std::slice::from_raw_parts(code, size) };
    match unsafe { &mut *env }.load(cpu, code_slice) {
        Ok(()) => 0,
        Err(e) => {
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn icicle_get_cpu_ptr(vm_ptr: *mut Icicle) -> *mut Cpu {
    if vm_ptr.is_null() {
        return ptr::null_mut();
    }
    unsafe { &mut *(*vm_ptr).vm.cpu }
}

// --- FFI Functions for Memory Hooks ---

#[no_mangle]
pub extern "C" fn icicle_add_mem_read_hook(
    vm_ptr: *mut Icicle,
    callback: MemReadHookFunction,
    data: *mut c_void,
    start_addr: u64,
    end_addr: u64,
) -> u32 {
    if vm_ptr.is_null() {
        return 0;
    }
    let vm = unsafe { &mut *vm_ptr };

    let wrapper = ReadHookWrapper {
        callback,
        user_data: data,
    };

    // Generate a new hook ID
    let hook_id = vm.mem_read_hooks.len() as u32;
    
    // Store the wrapper in our tracking map
    vm.mem_read_hooks.insert(hook_id, Box::new(wrapper.clone()));

    // Add the hook to the MMU
    match vm.vm.cpu.mem.add_read_after_hook(start_addr, end_addr, Box::new(wrapper)) {
        Some(_) => {
            hook_id
        }
        None => {
            // Clean up our tracking if MMU addition failed
            vm.mem_read_hooks.remove(&hook_id);
            0
        }
    }
}

#[no_mangle]
pub extern "C" fn icicle_add_mem_write_hook(
    vm_ptr: *mut Icicle,
    callback: MemWriteHookFunction,
    data: *mut c_void,
    start_addr: u64,
    end_addr: u64,
) -> u32 {
    if vm_ptr.is_null() {
        return 0;
    }
    let vm = unsafe { &mut *vm_ptr };

    let wrapper = WriteHookWrapper {
        callback,
        user_data: data,
    };

    // Generate a new hook ID
    let hook_id = vm.mem_write_hooks.len() as u32;
    
    // Store the wrapper in our tracking map
    vm.mem_write_hooks.insert(hook_id, Box::new(wrapper.clone()));

    // Add the hook to the MMU
    match vm.vm.cpu.mem.add_write_hook(start_addr, end_addr, Box::new(wrapper)) {
        Some(_) => {
            hook_id
        }
        None => {
            // Clean up our tracking if MMU addition failed
            vm.mem_write_hooks.remove(&hook_id);
            0
        }
    }
}

#[no_mangle]
pub extern "C" fn icicle_remove_mem_read_hook(
    vm_ptr: *mut Icicle,
    hook_id: u32,
) -> c_int {
    if vm_ptr.is_null() {
        return -1;
    }
    let vm = unsafe { &mut *vm_ptr };
    
    // Check if the hook exists in our tracking
    if !vm.mem_read_hooks.contains_key(&hook_id) {
        return -1;
    }

    // Remove the hook from our tracking
    vm.mem_read_hooks.remove(&hook_id);
    vm.vm.cpu.mem.tlb.clear(); // Clear TLB to ensure changes take effect
    
    0
}

#[no_mangle]
pub extern "C" fn icicle_remove_mem_write_hook(
    vm_ptr: *mut Icicle,
    hook_id: u32,
) -> c_int {
    if vm_ptr.is_null() {
        return -1;
    }
    let vm = unsafe { &mut *vm_ptr };
    
    // Check if the hook exists in our tracking
    if !vm.mem_write_hooks.contains_key(&hook_id) {
        return -1;
    }

    // Remove the hook from our tracking
    vm.mem_write_hooks.remove(&hook_id);
    vm.vm.cpu.mem.tlb.clear(); // Clear TLB to ensure changes take effect
    
    0
}


// Wrapper for ReadAfterHook
#[derive(Clone)]
struct ReadHookWrapper {
    callback: MemReadHookFunction,
    user_data: *mut c_void,
}

// We need to mark the wrapper as Send + Sync potentially if hooks can be called cross-thread,
// although for this FFI it might not be strictly necessary if called synchronously.
// For safety, let's assume the underlying hook mechanism might require it.
unsafe impl Send for ReadHookWrapper {}
unsafe impl Sync for ReadHookWrapper {}

impl ReadAfterHook for ReadHookWrapper {
    fn read(&mut self, _mmu: &mut Mmu, addr: u64, value: &[u8]) {
        let size = value.len() as u8;
        (self.callback)(self.user_data, addr, size, value.as_ptr());
    }
}

// Wrapper for WriteHook
#[derive(Clone)]
struct WriteHookWrapper {
    callback: MemWriteHookFunction,
    user_data: *mut c_void,
}

unsafe impl Send for WriteHookWrapper {}
unsafe impl Sync for WriteHookWrapper {}

impl WriteHook for WriteHookWrapper {
    fn write(&mut self, _mmu: &mut Mmu, addr: u64, value: &[u8]) {
        let size = value.len() as u8;
        let mut bytes = [0u8; 8];
        let len = size.min(8) as usize;
        bytes[..len].copy_from_slice(&value[..len]);
        let value_u64 = u64::from_le_bytes(bytes);
        (self.callback)(self.user_data, addr, size, value_u64);
    }
}

#[repr(C)]
pub struct CpuSnapshot {
    regs: *mut Regs,
    args: [u128; 8],
    shadow_stack: *mut ShadowStack,
    exception_code: u32,
    exception_value: u64,
    pending_exception: *mut Option<Exception>,
    icount: u64,
    block_id: u64,
    block_offset: u64,
}

#[no_mangle]
pub extern "C" fn icicle_cpu_snapshot(vm: *mut Icicle) -> *mut CpuSnapshot {
    if vm.is_null() {
        return std::ptr::null_mut();
    }

    let vm = unsafe { &*vm };
    let snapshot = vm.vm.cpu.snapshot();
    
    // Convert the snapshot into a C-compatible format
    let c_snapshot = Box::new(CpuSnapshot {
        regs: Box::into_raw(Box::new((*snapshot).regs.clone())),
        args: (*snapshot).args,
        shadow_stack: Box::into_raw(Box::new((*snapshot).shadow_stack.clone())),
        exception_code: (*snapshot).exception.code,
        exception_value: (*snapshot).exception.value,
        pending_exception: Box::into_raw(Box::new((*snapshot).pending_exception.clone())),
        icount: (*snapshot).icount,
        block_id: (*snapshot).block_id,
        block_offset: (*snapshot).block_offset,
    });

    Box::into_raw(c_snapshot)
}

#[no_mangle]
pub extern "C" fn icicle_cpu_restore(vm: *mut Icicle, snapshot: *const CpuSnapshot) -> i32 {
    if vm.is_null() || snapshot.is_null() {
        return -1;
    }

    let vm = unsafe { &mut *vm };
    let snapshot = unsafe { &*snapshot };

    // Create a new CPU snapshot with the correct types
    let rust_snapshot = Box::new(icicle_cpu::CpuSnapshot {
        regs: unsafe { (*snapshot.regs).clone() },
        args: snapshot.args,
        shadow_stack: unsafe { (*snapshot.shadow_stack).clone() },
        exception: Exception {
            code: snapshot.exception_code,
            value: snapshot.exception_value,
        },
        pending_exception: unsafe { (*snapshot.pending_exception).clone() },
        icount: snapshot.icount,
        block_id: snapshot.block_id,
        block_offset: snapshot.block_offset,
    });

    vm.vm.cpu.restore(&*rust_snapshot);
    0
}

#[no_mangle]
pub extern "C" fn icicle_cpu_snapshot_free(snapshot: *mut CpuSnapshot) {
    if !snapshot.is_null() {
        unsafe {
            let snapshot = Box::from_raw(snapshot);
            Box::from_raw(snapshot.regs);
            Box::from_raw(snapshot.shadow_stack);
            Box::from_raw(snapshot.pending_exception);
        }
    }
}

#[repr(C)]
pub struct VmSnapshot {
    cpu: *mut CpuSnapshot,
    mem: *mut icicle_vm::Snapshot,
    env: *mut Box<dyn std::any::Any>,
}

#[no_mangle]
pub extern "C" fn icicle_vm_snapshot(vm: *mut Icicle) -> *mut VmSnapshot {
    if vm.is_null() {
        return std::ptr::null_mut();
    }

    let vm = unsafe { &mut *vm };
    let snapshot = vm.vm.snapshot();

    // Convert the snapshot into a C-compatible format
    let c_snapshot = Box::new(VmSnapshot {
        cpu: Box::into_raw(Box::new(CpuSnapshot {
            regs: Box::into_raw(Box::new((*snapshot.cpu).regs.clone())),
            args: (*snapshot.cpu).args,
            shadow_stack: Box::into_raw(Box::new((*snapshot.cpu).shadow_stack.clone())),
            exception_code: (*snapshot.cpu).exception.code,
            exception_value: (*snapshot.cpu).exception.value,
            pending_exception: Box::into_raw(Box::new((*snapshot.cpu).pending_exception.clone())),
            icount: (*snapshot.cpu).icount,
            block_id: (*snapshot.cpu).block_id,
            block_offset: (*snapshot.cpu).block_offset,
        })),
        mem: Box::into_raw(Box::new(snapshot)),
        env: Box::into_raw(Box::new(Box::new(()))), // Empty environment for now
    });

    Box::into_raw(c_snapshot)
}

#[no_mangle]
pub extern "C" fn icicle_vm_restore(vm: *mut Icicle, snapshot: *const VmSnapshot) -> i32 {
    if vm.is_null() || snapshot.is_null() {
        return -1;
    }

    let vm = unsafe { &mut *vm };
    let snapshot = unsafe { &*snapshot };
    let snapshot = unsafe { &*snapshot.mem };

    vm.vm.restore(snapshot);
    0
}

#[no_mangle]
pub extern "C" fn icicle_vm_snapshot_free(snapshot: *mut VmSnapshot) {
    if !snapshot.is_null() {
        unsafe {
            let snapshot = Box::from_raw(snapshot);
            icicle_cpu_snapshot_free(snapshot.cpu);
            Box::from_raw(snapshot.mem);
            Box::from_raw(snapshot.env);
        }
    }
}

// Generates a backtrace of function calls using debug information.
// Returns a newly allocated C string that must be freed with icicle_free_string.
// Returns NULL on failure or if no debug info is available.
#[no_mangle]
pub extern "C" fn icicle_get_backtrace(vm_ptr: *mut Icicle, max_frames: usize) -> *mut c_char {
    if vm_ptr.is_null() {
        return ptr::null_mut();
    }
    
    let vm = unsafe { &mut *vm_ptr };
    let backtrace_str = vm.get_backtrace(max_frames);
    
    // Convert Rust string to C string
    match CString::new(backtrace_str) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

// Helper to free strings allocated by string-returning functions like icicle_get_backtrace
#[no_mangle]
pub extern "C" fn icicle_free_string(string: *mut c_char) {
    if !string.is_null() {
        unsafe {
            let _ = CString::from_raw(string);
        }
    }
}

// Generates a disassembly dump of all code in the VM
// Returns a newly allocated C string that must be freed with icicle_free_string
// Returns NULL on failure
#[no_mangle]
pub extern "C" fn icicle_dump_disasm(vm_ptr: *const Icicle) -> *mut c_char {
    if vm_ptr.is_null() {
        return ptr::null_mut();
    }
    
    let vm = unsafe { &*vm_ptr };
    match vm.dump_disasm() {
        Ok(disasm_str) => match CString::new(disasm_str) {
            Ok(c_str) => c_str.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        Err(_) => ptr::null_mut(),
    }
}

// Returns the disassembly of the current code being executed
// Returns a newly allocated C string that must be freed with icicle_free_string
// Returns NULL on failure
#[no_mangle]
pub extern "C" fn icicle_current_disasm(vm_ptr: *const Icicle) -> *mut c_char {
    if vm_ptr.is_null() {
        return ptr::null_mut();
    }
    
    let vm = unsafe { &*vm_ptr };
    let disasm_str = vm.current_disasm();
    
    match CString::new(disasm_str) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

// Steps backward in execution by the specified number of instructions.
// Returns the run status if successful, or -1 (as u32) if there are no snapshots to step back to.
#[no_mangle]
pub extern "C" fn icicle_step_back(vm_ptr: *mut Icicle, count: u64) -> u32 {
    if vm_ptr.is_null() {
        return u32::MAX; // Return -1 as u32
    }
    
    let vm = unsafe { &mut *vm_ptr };
    match vm.step_back(count) {
        Some(status) => status as u32,
        None => u32::MAX, // Return -1 as u32
    }
}

// Goes to a specific instruction count if snapshots are available.
// Returns the run status if successful, or -1 (as u32) if there are no snapshots that can reach the target.
#[no_mangle]
pub extern "C" fn icicle_goto_icount(vm_ptr: *mut Icicle, target_icount: u64) -> u32 {
    if vm_ptr.is_null() {
        return u32::MAX; // Return -1 as u32
    }
    
    let vm = unsafe { &mut *vm_ptr };
    match vm.goto_icount(target_icount) {
        Some(status) => status as u32,
        None => u32::MAX, // Return -1 as u32
    }
}

// Saves a snapshot at the current execution state.
// Snapshots are required for step_back and goto_icount functionality.
#[no_mangle]
pub extern "C" fn icicle_save_snapshot(vm_ptr: *mut Icicle) -> c_int {
    if vm_ptr.is_null() {
        return -1;
    }
    
    let vm = unsafe { &mut *vm_ptr };
    vm.save_snapshot();
    0 // Return success
}

// Log write hook wrapper for memory write logging with a label
struct LabeledWriteHook {
    name: CString,
    callback: LogWriteHookFunction,
    user_data: *mut c_void,
}

impl Clone for LabeledWriteHook {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            callback: self.callback,
            user_data: self.user_data,
        }
    }
}

impl WriteHook for LabeledWriteHook {
    fn write(&mut self, _mmu: &mut Mmu, addr: u64, value: &[u8]) {
        let val = if value.len() <= 8 {
            // Convert bytes to u64 (assumes little-endian)
            let mut val: u64 = 0;
            for (i, &byte) in value.iter().enumerate() {
                val |= (byte as u64) << (i * 8);
            }
            val
        } else {
            // For larger writes, we can only show part of the data
            let mut val: u64 = 0;
            for i in 0..8 {
                if i < value.len() {
                    val |= (value[i] as u64) << (i * 8);
                }
            }
            val
        };

        (self.callback)(self.user_data, self.name.as_ptr(), addr, value.len() as u8, val);
    }
}

// Structure to hold register hook data
struct RegisterHook {
    name: CString,
    callback: LogRegsHookFunction,
    user_data: *mut c_void,
    reg_names: Vec<CString>,
}

impl Clone for RegisterHook {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            callback: self.callback,
            user_data: self.user_data,
            reg_names: self.reg_names.clone(),
        }
    }
}

/// Adds instrumentation to log memory writes at a specific address with a label
/// 
/// When a write occurs to the monitored address, the callback is invoked with:
/// - data: User-provided context pointer
/// - name: The label assigned to this memory location
/// - address: The memory address that was written to
/// - size: Size of the write in bytes
/// - value: The value written (up to 64 bits)
///
/// Returns a unique hook ID on success, 0 on failure.
#[no_mangle]
pub extern "C" fn icicle_debug_log_write(
    vm_ptr: *mut Icicle,
    name: *const c_char,
    address: u64,
    size: u8,
    callback: LogWriteHookFunction,
    data: *mut c_void,
) -> u32 {
    if vm_ptr.is_null() || name.is_null() {
        return 0;
    }
    let vm = unsafe { &mut *vm_ptr };
    
    // Convert C string to Rust
    let c_str = unsafe { CStr::from_ptr(name) };
    let name_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return 0, // Invalid UTF-8 string
    };
    
    // Create wrapper with label
    let hook = LabeledWriteHook {
        name: CString::new(name_str).unwrap_or_else(|_| CString::new("unknown").unwrap()),
        callback,
        user_data: data,
    };
    
    // Generate a new hook ID
    let hook_id = vm.next_mem_hook_id;
    vm.next_mem_hook_id += 1;
    
    // Add the hook to the MMU
    let end_addr = address + size as u64;
    match vm.vm.cpu.mem.add_write_hook(address, end_addr, Box::new(hook.clone())) {
        Some(_) => {
            // Store the hook in our tracking map for future reference/removal
            vm.mem_write_hooks.insert(hook_id, Box::new(hook));
            hook_id
        }
        None => 0 // Failed to add hook
    }
}

/// Adds instrumentation to log register values at a specific program counter address
/// 
/// When execution reaches the specified address, the callback is invoked with:
/// - data: User-provided context pointer
/// - name: The label assigned to this checkpoint
/// - address: The address where execution triggered the hook
/// - num_regs: Number of registers being reported
/// - reg_names: Array of register name strings
/// - reg_values: Array of register values
///
/// Returns a unique hook ID on success, 0 on failure.
#[no_mangle]
pub extern "C" fn icicle_debug_log_regs(
    vm_ptr: *mut Icicle,
    name: *const c_char,
    address: u64,
    num_regs: usize,
    reg_names: *const *const c_char,
    callback: LogRegsHookFunction,
    data: *mut c_void,
) -> u32 {
    if vm_ptr.is_null() || name.is_null() || reg_names.is_null() || num_regs == 0 {
        return 0;
    }
    
    let vm = unsafe { &mut *vm_ptr };
    
    // Convert C string to Rust
    let c_str = unsafe { CStr::from_ptr(name) };
    let name_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return 0, // Invalid UTF-8 string
    };
    
    // Convert register names
    let mut rust_reg_names = Vec::with_capacity(num_regs);
    for i in 0..num_regs {
        let reg_name_ptr = unsafe { *reg_names.add(i) };
        if reg_name_ptr.is_null() {
            continue;
        }
        
        let reg_c_str = unsafe { CStr::from_ptr(reg_name_ptr) };
        match reg_c_str.to_str() {
            Ok(s) => {
                // Verify this register exists
                if reg_find(vm, s).is_err() {
                    continue; // Skip invalid registers
                }
                match CString::new(s) {
                    Ok(cs) => rust_reg_names.push(cs),
                    Err(_) => continue,
                }
            }
            Err(_) => continue,
        }
    }
    
    if rust_reg_names.is_empty() {
        return 0; // No valid registers found
    }
    
    // Create the register hook structure
    let reg_hook = RegisterHook {
        name: CString::new(name_str).unwrap_or_else(|_| CString::new("unknown").unwrap()),
        callback,
        user_data: data,
        reg_names: rust_reg_names.clone(),
    };
    
    // Create closure for VM hook
    let hook_fn = move |cpu: &mut Cpu, addr: u64| {
        // Create arrays for the callback
        let mut c_reg_names: Vec<*const c_char> = Vec::with_capacity(rust_reg_names.len());
        let mut reg_values: Vec<u64> = Vec::with_capacity(rust_reg_names.len());
        
        // Collect register values
        for reg_name in &rust_reg_names {
            let var = match cpu.arch.sleigh.get_reg(reg_name.to_str().unwrap_or("")) {
                Some(reg) => reg.var,
                None => continue,
            };
            
            let value = cpu.read_reg(var);
            reg_values.push(value);
            c_reg_names.push(reg_name.as_ptr());
        }
        
        // Call the C callback
        if !c_reg_names.is_empty() {
            unsafe {
                (reg_hook.callback)(
                    reg_hook.user_data,
                    reg_hook.name.as_ptr(),
                    addr,
                    c_reg_names.len(),
                    c_reg_names.as_ptr(),
                    reg_values.as_ptr(),
                );
            }
        }
    };
    
    // Add hook to VM
    let hook_id = vm.next_execution_hook_id;
    vm.next_execution_hook_id += 1;
    
    // Add execution hook to the VM
    let internal_hook_id = vm.vm.cpu.add_hook(Box::new(hook_fn.clone()));
    // Register to activate the hook at specific address
    icicle_vm::injector::register_block_hook_injector(&mut vm.vm, address, address + 1, internal_hook_id);
    
    // Store for future reference
    vm.execution_hooks.insert(hook_id, Box::new(hook_fn));
    
    hook_id
}

// Default debug hook that will be used if environment variable configuration is used
extern "C" fn default_log_write_hook(data: *mut c_void, name: *const c_char, address: u64, size: u8, value: u64) {
    let name_str = unsafe { 
        if name.is_null() { 
            "unknown" 
        } else { 
            CStr::from_ptr(name).to_str().unwrap_or("invalid") 
        }
    };
    eprintln!("[WRITE] {}@{:#x} = {:#x} (size={})", name_str, address, value, size);
}

// Default debug hook for register values
extern "C" fn default_log_regs_hook(data: *mut c_void, name: *const c_char, address: u64, num_regs: usize, reg_names: *const *const c_char, reg_values: *const u64) {
    let name_str = unsafe { 
        if name.is_null() { 
            "unknown" 
        } else { 
            CStr::from_ptr(name).to_str().unwrap_or("invalid") 
        }
    };
    eprintln!("[REGS] {}@{:#x}:", name_str, address);
    
    for i in 0..num_regs {
        unsafe {
            let reg_name = if reg_names.is_null() { 
                "?" 
            } else { 
                let ptr = *reg_names.add(i);
                if ptr.is_null() {
                    "?"
                } else {
                    CStr::from_ptr(ptr).to_str().unwrap_or("?")
                }
            };
            let value = if reg_values.is_null() { 0 } else { *reg_values.add(i) };
            eprintln!("  {} = {:#x}", reg_name, value);
        }
    }
}

/// Parse a memory write hook definition in the format "<name>=<address>:<size>"
fn parse_write_hook(entry: &str) -> Option<(&str, u64, u8)> {
    let entry = entry.trim();
    if entry.is_empty() {
        return None;
    }
    let (name, addr_size) = entry.split_once('=')?;
    let (addr, size) = addr_size.split_once(':')?;

    let addr = icicle_vm::cpu::utils::parse_u64_with_prefix(addr)?;
    let size: u8 = size.parse().ok()?;

    Some((name, addr, size))
}

/// Parse a register hook definition in the format "<name>@<address>=<reglist>"
fn parse_reg_print_hook(entry: &str) -> Option<(&str, u64, Vec<&str>)> {
    let entry = entry.trim();
    if entry.is_empty() {
        return None;
    }

    let (target, reglist) = entry.split_once('=')?;
    let (name, pc) = target.split_once('@')?;

    let pc = icicle_vm::cpu::utils::parse_u64_with_prefix(pc)?;
    let regs = reglist.split(',').map(str::trim).collect();

    Some((name, pc, regs))
}

/// Set up debug instrumentation based on environment variables
/// This emulates the behavior of add_debug_instrumentation in icicle-fuzzing
///
/// Supported environment variables:
/// - ICICLE_LOG_WRITES: A semicolon-separated list of "<name>=<address>:<size>" entries
/// - ICICLE_LOG_REGS: A semicolon-separated list of "<name>@<address>=<reg1>,<reg2>,...<regN>" entries
/// - BREAKPOINTS: A comma-separated list of addresses to stop execution at
#[no_mangle]
pub extern "C" fn icicle_add_debug_instrumentation(vm_ptr: *mut Icicle) -> c_int {
    if vm_ptr.is_null() {
        return -1;
    }
    let vm = unsafe { &mut *vm_ptr };
    
    let mut hook_count = 0;
    
    // Process ICICLE_LOG_WRITES environment variable
    if let Ok(entries) = std::env::var("ICICLE_LOG_WRITES") {
        for entry in entries.split(';') {
            match parse_write_hook(entry) {
                Some((name, addr, size)) => {
                    // Create string for logging
                    let hook_id = icicle_debug_log_write(
                        vm_ptr,
                        CString::new(name).unwrap_or_else(|_| CString::new("unknown").unwrap()).as_ptr(),
                        addr,
                        size,
                        default_log_write_hook,
                        std::ptr::null_mut(),
                    );
                    if hook_id > 0 {
                        hook_count += 1;
                    }
                }
                None => eprintln!("Invalid write hook format: {}", entry),
            }
        }
    }
    
    // Process ICICLE_LOG_REGS environment variable
    if let Ok(entries) = std::env::var("ICICLE_LOG_REGS") {
        for entry in entries.split(';') {
            match parse_reg_print_hook(entry) {
                Some((name, addr, reglist)) => {
                    // Convert register list to C-compatible format
                    let c_reg_names: Vec<CString> = reglist
                        .iter()
                        .map(|&r| CString::new(r).unwrap_or_else(|_| CString::new("unknown").unwrap()))
                        .collect();
                    
                    let c_reg_ptrs: Vec<*const c_char> = c_reg_names
                        .iter()
                        .map(|s| s.as_ptr())
                        .collect();
                    
                    let hook_id = icicle_debug_log_regs(
                        vm_ptr,
                        CString::new(name).unwrap_or_else(|_| CString::new("unknown").unwrap()).as_ptr(),
                        addr,
                        c_reg_names.len(),
                        c_reg_ptrs.as_ptr(),
                        default_log_regs_hook,
                        std::ptr::null_mut(),
                    );
                    if hook_id > 0 {
                        hook_count += 1;
                    }
                }
                None => eprintln!("Invalid register hook format: {}", entry),
            }
        }
    }
    
    // Process BREAKPOINTS environment variable
    if let Ok(entries) = std::env::var("BREAKPOINTS") {
        for entry in entries.split(',') {
            match icicle_vm::cpu::utils::parse_u64_with_prefix(entry.trim()) {
                Some(addr) => {
                    if vm.add_breakpoint(addr) {
                        hook_count += 1;
                    }
                }
                None => eprintln!("Invalid breakpoint: {}", entry),
            }
        }
    }
    
    hook_count as c_int
}

// Implementation of coverage-related functions

/// Get the coverage map from the VM
#[no_mangle]
pub extern "C" fn icicle_get_coverage_map(
    vm_ptr: *mut Icicle,
    out_size: *mut usize,
) -> *mut u8 {
    if vm_ptr.is_null() || out_size.is_null() {
        return ptr::null_mut();
    }
    let vm = unsafe { &mut *vm_ptr };
    
    // We'll use a simple coverage map stored in the VM instance
    // This is populated during basic block execution via a hook
    if vm.coverage_map.is_empty() {
        return ptr::null_mut();
    }
    
    let mut coverage_map = vm.coverage_map.clone();
    
    // Set the output size
    unsafe { *out_size = coverage_map.len() };
    
    // Move ownership to C
    let ptr = coverage_map.as_mut_ptr();
    std::mem::forget(coverage_map);
    
    ptr
}

/// Set the coverage mode for instrumentation
#[no_mangle]
pub extern "C" fn icicle_set_coverage_mode(
    vm_ptr: *mut Icicle,
    mode: CoverageMode,
) -> c_int {
    if vm_ptr.is_null() {
        return -1;
    }
    let vm = unsafe { &mut *vm_ptr };
    
    // Clear existing coverage data
    vm.coverage_map.clear();
    
    // Initialize a coverage map based on the mode
    // For block/edge coverage modes, we use a bit map
    // For count modes, we use a counter map
    let size = match mode {
        CoverageMode::Blocks | CoverageMode::Edges => 4096, // 32K bits
        CoverageMode::BlockCounts | CoverageMode::EdgeCounts => 4096 * 2, // 4K counters
    };
    
    vm.coverage_map = vec![0; size];
    vm.coverage_mode = mode;
    
    // If we already have an execution hook, remove it
    if let Some(id) = vm.coverage_hook_id {
        icicle_remove_execution_hook(vm_ptr, id);
        vm.coverage_hook_id = None;
    }
    
    // Add a new execution hook based on the mode
    let hook_id = add_coverage_hook(vm_ptr, mode);
    if hook_id == 0 {
        return -1;
    }
    
    vm.coverage_hook_id = Some(hook_id);
    0
}

// Internal function to add the appropriate coverage hook
fn add_coverage_hook(vm_ptr: *mut Icicle, mode: CoverageMode) -> u32 {
    let vm = unsafe { &mut *vm_ptr };
    
    // Create a weak reference to the coverage map
    let coverage_map_ptr = &mut vm.coverage_map as *mut Vec<u8>;
    
    // Since we can't modify the CPU directly, we'll use our execution hook system
    let hook_fn: Box<dyn FnMut(&mut Cpu, u64)> = match mode {
        CoverageMode::Blocks => {
            Box::new(move |_cpu: &mut Cpu, pc: u64| {
                // Calculate a hash/index based on the PC
                let coverage_map = unsafe { &mut *coverage_map_ptr };
                let idx = (pc as usize) % (coverage_map.len() * 8);
                let byte_idx = idx / 8;
                let bit_idx = idx % 8;
                
                if byte_idx < coverage_map.len() {
                    coverage_map[byte_idx] |= 1 << bit_idx;
                }
            })
        },
        CoverageMode::Edges => {
            // For edge coverage, we need to track the previous block
            let mut prev_pc = 0;
            Box::new(move |_cpu: &mut Cpu, pc: u64| {
                // Calculate a hash/index based on the edge (prev_pc -> pc)
                let coverage_map = unsafe { &mut *coverage_map_ptr };
                let edge_hash = ((prev_pc >> 4) ^ pc) as usize; 
                let idx = edge_hash % (coverage_map.len() * 8);
                let byte_idx = idx / 8;
                let bit_idx = idx % 8;
                
                if byte_idx < coverage_map.len() {
                    coverage_map[byte_idx] |= 1 << bit_idx;
                }
                
                prev_pc = pc;
            })
        },
        CoverageMode::BlockCounts => {
            Box::new(move |_cpu: &mut Cpu, pc: u64| {
                // Calculate a hash/index based on the PC
                let coverage_map = unsafe { &mut *coverage_map_ptr };
                let idx = (pc as usize) % (coverage_map.len() / 2);
                let byte_idx = idx * 2;
                
                if byte_idx + 1 < coverage_map.len() {
                    // Increment the counter (2 bytes per counter)
                    let counter = u16::from_le_bytes([
                        coverage_map[byte_idx],
                        coverage_map[byte_idx + 1]
                    ]);
                    
                    // Don't overflow the counter
                    if counter < u16::MAX {
                        let new_counter = counter + 1;
                        let bytes = new_counter.to_le_bytes();
                        coverage_map[byte_idx] = bytes[0];
                        coverage_map[byte_idx + 1] = bytes[1];
                    }
                }
            })
        },
        CoverageMode::EdgeCounts => {
            // Edge counts need to track previous block
            let mut prev_pc = 0;
            Box::new(move |_cpu: &mut Cpu, pc: u64| {
                // Calculate a hash/index based on the edge (prev_pc -> pc)
                let coverage_map = unsafe { &mut *coverage_map_ptr };
                let edge_hash = ((prev_pc >> 4) ^ pc) as usize;
                let idx = edge_hash % (coverage_map.len() / 2);
                let byte_idx = idx * 2;
                
                if byte_idx + 1 < coverage_map.len() {
                    // Increment the counter (2 bytes per counter)
                    let counter = u16::from_le_bytes([
                        coverage_map[byte_idx],
                        coverage_map[byte_idx + 1]
                    ]);
                    
                    // Don't overflow the counter
                    if counter < u16::MAX {
                        let new_counter = counter + 1;
                        let bytes = new_counter.to_le_bytes();
                        coverage_map[byte_idx] = bytes[0];
                        coverage_map[byte_idx + 1] = bytes[1];
                    }
                }
                
                prev_pc = pc;
            })
        },
    };
    
    // Register the hook with the system
    let internal_id = vm.vm.cpu.add_hook(hook_fn);
    
    // Register a hook injector if we have a range specified
    if vm.coverage_start_addr < vm.coverage_end_addr {
        icicle_vm::injector::register_block_hook_injector(
            &mut vm.vm, 
            vm.coverage_start_addr, 
            vm.coverage_end_addr, 
            internal_id
        );
    } else {
        // Register for all addresses
        icicle_vm::injector::register_block_hook_injector(
            &mut vm.vm, 
            0, 
            u64::MAX, 
            internal_id
        );
    }
    
    // Generate and store the hook ID for later removal
    let ffi_hook_id = vm.next_execution_hook_id;
    
    // We need to save a separate hook function for the FFI layer
    // since the original hook_fn is consumed by the add_hook call
    let hook_fn2: Box<dyn FnMut(&mut Cpu, u64)> = match mode {
        CoverageMode::Blocks => {
            Box::new(move |_cpu: &mut Cpu, pc: u64| {
                // Calculate a hash/index based on the PC
                let coverage_map = unsafe { &mut *coverage_map_ptr };
                let idx = (pc as usize) % (coverage_map.len() * 8);
                let byte_idx = idx / 8;
                let bit_idx = idx % 8;
                
                if byte_idx < coverage_map.len() {
                    coverage_map[byte_idx] |= 1 << bit_idx;
                }
            })
        },
        CoverageMode::Edges => {
            // For edge coverage, we need to track the previous block
            let mut prev_pc = 0;
            Box::new(move |_cpu: &mut Cpu, pc: u64| {
                // Calculate a hash/index based on the edge (prev_pc -> pc)
                let coverage_map = unsafe { &mut *coverage_map_ptr };
                let edge_hash = ((prev_pc >> 4) ^ pc) as usize; 
                let idx = edge_hash % (coverage_map.len() * 8);
                let byte_idx = idx / 8;
                let bit_idx = idx % 8;
                
                if byte_idx < coverage_map.len() {
                    coverage_map[byte_idx] |= 1 << bit_idx;
                }
                
                prev_pc = pc;
            })
        },
        CoverageMode::BlockCounts => {
            Box::new(move |_cpu: &mut Cpu, pc: u64| {
                // Calculate a hash/index based on the PC
                let coverage_map = unsafe { &mut *coverage_map_ptr };
                let idx = (pc as usize) % (coverage_map.len() / 2);
                let byte_idx = idx * 2;
                
                if byte_idx + 1 < coverage_map.len() {
                    // Increment the counter (2 bytes per counter)
                    let counter = u16::from_le_bytes([
                        coverage_map[byte_idx],
                        coverage_map[byte_idx + 1]
                    ]);
                    
                    // Don't overflow the counter
                    if counter < u16::MAX {
                        let new_counter = counter + 1;
                        let bytes = new_counter.to_le_bytes();
                        coverage_map[byte_idx] = bytes[0];
                        coverage_map[byte_idx + 1] = bytes[1];
                    }
                }
            })
        },
        CoverageMode::EdgeCounts => {
            // Edge counts need to track previous block
            let mut prev_pc = 0;
            Box::new(move |_cpu: &mut Cpu, pc: u64| {
                // Calculate a hash/index based on the edge (prev_pc -> pc)
                let coverage_map = unsafe { &mut *coverage_map_ptr };
                let edge_hash = ((prev_pc >> 4) ^ pc) as usize;
                let idx = edge_hash % (coverage_map.len() / 2);
                let byte_idx = idx * 2;
                
                if byte_idx + 1 < coverage_map.len() {
                    // Increment the counter (2 bytes per counter)
                    let counter = u16::from_le_bytes([
                        coverage_map[byte_idx],
                        coverage_map[byte_idx + 1]
                    ]);
                    
                    // Don't overflow the counter
                    if counter < u16::MAX {
                        let new_counter = counter + 1;
                        let bytes = new_counter.to_le_bytes();
                        coverage_map[byte_idx] = bytes[0];
                        coverage_map[byte_idx + 1] = bytes[1];
                    }
                }
                
                prev_pc = pc;
            })
        },
    };
    
    vm.execution_hooks.insert(ffi_hook_id, hook_fn2);
    vm.next_execution_hook_id += 1;
    
    ffi_hook_id
}

/// Get the current coverage mode
#[no_mangle]
pub extern "C" fn icicle_get_coverage_mode(
    vm_ptr: *mut Icicle,
) -> CoverageMode {
    if vm_ptr.is_null() {
        return CoverageMode::Blocks; // Default
    }
    let vm = unsafe { &*vm_ptr };
    vm.coverage_mode
}

/// Enable instrumentation for a specific address range
#[no_mangle]
pub extern "C" fn icicle_enable_instrumentation(
    vm_ptr: *mut Icicle,
    start_addr: u64,
    end_addr: u64,
) -> c_int {
    if vm_ptr.is_null() || start_addr >= end_addr {
        return -1;
    }
    let vm = unsafe { &mut *vm_ptr };
    
    // Store the instrumentation range
    vm.coverage_start_addr = start_addr;
    vm.coverage_end_addr = end_addr;
    
    // Re-apply the current coverage mode with the new range
    let current_mode = vm.coverage_mode;
    icicle_set_coverage_mode(vm_ptr, current_mode);
    
    vm.instrumentation_enabled = true;
    0
}

/// Set the number of context bits for edge coverage
#[no_mangle]
pub extern "C" fn icicle_set_context_bits(
    vm_ptr: *mut Icicle,
    bits: u8,
) -> c_int {
    if vm_ptr.is_null() || bits > 16 {
        return -1;
    }
    let vm = unsafe { &mut *vm_ptr };
    
    // Store the context bits setting
    vm.context_bits = bits;
    
    // We need to re-apply the coverage mode if it's edge-based
    if vm.coverage_mode == CoverageMode::Edges || vm.coverage_mode == CoverageMode::EdgeCounts {
        // Re-create the coverage hook with context bits
        icicle_set_coverage_mode(vm_ptr, vm.coverage_mode);
    }
    
    0
}

/// Get the current context bits setting
#[no_mangle]
pub extern "C" fn icicle_get_context_bits(
    vm_ptr: *mut Icicle,
) -> u8 {
    if vm_ptr.is_null() {
        return 0;
    }
    let vm = unsafe { &*vm_ptr };
    vm.context_bits
}

/// Enable comparison coverage at the specified level
#[no_mangle]
pub extern "C" fn icicle_enable_compcov(
    vm_ptr: *mut Icicle,
    level: u8,
) -> c_int {
    if vm_ptr.is_null() {
        return -1;
    }
    let vm = unsafe { &mut *vm_ptr };
    
    // Store the comparison coverage level
    vm.compcov_level = level;
    
    // In a more complete implementation, we would register hooks for comparison instructions
    // This is a simplified version that just stores the setting
    0
}

/// Get the current compcov level
#[no_mangle]
pub extern "C" fn icicle_get_compcov_level(
    vm_ptr: *mut Icicle,
) -> u8 {
    if vm_ptr.is_null() {
        return 0;
    }
    let vm = unsafe { &*vm_ptr };
    vm.compcov_level
}

/// Enable edge coverage
#[no_mangle]
pub extern "C" fn icicle_enable_edge_coverage(
    vm_ptr: *mut Icicle,
    enable: bool,
) -> c_int {
    if vm_ptr.is_null() {
        return -1;
    }
    let vm = unsafe { &mut *vm_ptr };
    
    // Update the coverage mode based on the edge setting
    if enable {
        if vm.coverage_mode == CoverageMode::Blocks {
            icicle_set_coverage_mode(vm_ptr, CoverageMode::Edges);
        } else if vm.coverage_mode == CoverageMode::BlockCounts {
            icicle_set_coverage_mode(vm_ptr, CoverageMode::EdgeCounts);
        }
    } else {
        if vm.coverage_mode == CoverageMode::Edges {
            icicle_set_coverage_mode(vm_ptr, CoverageMode::Blocks);
        } else if vm.coverage_mode == CoverageMode::EdgeCounts {
            icicle_set_coverage_mode(vm_ptr, CoverageMode::BlockCounts);
        }
    }
    
    0
}

/// Check if edge coverage is enabled
#[no_mangle]
pub extern "C" fn icicle_has_edge_coverage(
    vm_ptr: *mut Icicle,
) -> bool {
    if vm_ptr.is_null() {
        return false;
    }
    let vm = unsafe { &*vm_ptr };
    vm.coverage_mode == CoverageMode::Edges || vm.coverage_mode == CoverageMode::EdgeCounts
}

/// Enable block coverage only (and optionally disable edge coverage)
#[no_mangle]
pub extern "C" fn icicle_enable_block_coverage(
    vm_ptr: *mut Icicle,
    only_blocks: bool,
) -> c_int {
    if vm_ptr.is_null() {
        return -1;
    }
    let vm = unsafe { &mut *vm_ptr };
    
    // Turn off edge coverage if only_blocks is true
    if only_blocks {
        if vm.coverage_mode == CoverageMode::Edges {
            icicle_set_coverage_mode(vm_ptr, CoverageMode::Blocks);
        } else if vm.coverage_mode == CoverageMode::EdgeCounts {
            icicle_set_coverage_mode(vm_ptr, CoverageMode::BlockCounts);
        }
    }
    
    0
}

/// Check if block coverage is being used
#[no_mangle]
pub extern "C" fn icicle_has_block_coverage(
    vm_ptr: *mut Icicle,
) -> bool {
    if vm_ptr.is_null() {
        return false;
    }
    let vm = unsafe { &*vm_ptr };
    vm.coverage_mode == CoverageMode::Blocks || vm.coverage_mode == CoverageMode::BlockCounts
}

/// Check if count-based coverage is enabled
#[no_mangle]
pub extern "C" fn icicle_has_counts_coverage(
    vm_ptr: *mut Icicle,
) -> bool {
    if vm_ptr.is_null() {
        return false;
    }
    let vm = unsafe { &*vm_ptr };
    vm.coverage_mode == CoverageMode::BlockCounts || vm.coverage_mode == CoverageMode::EdgeCounts
}

/// Reset the coverage map
#[no_mangle]
pub extern "C" fn icicle_reset_coverage(
    vm_ptr: *mut Icicle,
) {
    if vm_ptr.is_null() {
        return;
    }
    let vm = unsafe { &mut *vm_ptr };
    
    // Reset the coverage map to all zeros
    for byte in &mut vm.coverage_map {
        *byte = 0;
    }
}

// Fix the unsafe marker that was previously removed
unsafe impl Send for LabeledWriteHook {}
unsafe impl Sync for LabeledWriteHook {}

#[no_mangle]
pub extern "C" fn icicle_reg_read_bytes(
    vm_ptr: *mut Icicle,
    reg_name: *const c_char,
    out_buffer: *mut u8, // Use u8* for raw bytes
    buffer_size: usize,
    out_bytes_read: *mut usize,
) -> c_int {
    if vm_ptr.is_null() || reg_name.is_null() || out_buffer.is_null() || out_bytes_read.is_null() {
        return -1;
    }
    let vm = unsafe { &mut *vm_ptr };
    let c_str = unsafe { CStr::from_ptr(reg_name) };
    let name = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return -1, // Invalid UTF-8
    };

    match reg_find(vm, name) {
        Ok(reg) => {
            let reg_size = reg.var.size as usize;
            // Ensure the provided buffer is large enough
            if buffer_size < reg_size {
                return -1; // Buffer too small
            }

            // Read the raw bytes directly from the Regs storage
            if let Some(bytes) = vm.vm.cpu.regs.get(reg.var) {
                 // Check length just in case, though reg.var.size should be correct
                if bytes.len() != reg_size {
                     eprintln!("Warning: Register size mismatch for {}", name);
                     return -1;
                }
                unsafe {
                    // Copy the bytes to the C buffer
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buffer, reg_size);
                    // Write the actual number of bytes read
                    *out_bytes_read = reg_size;
                }
                0 // Success
            } else {
                -1 // Should not happen if reg_find succeeded, but handle defensively
            }
        }
        Err(_) => -1, // Register not found
    }
}

#[no_mangle]
pub extern "C" fn icicle_reg_write_bytes(
    vm_ptr: *mut Icicle,
    reg_name: *const c_char,
    buffer: *const u8,
    buffer_size: usize,
) -> c_int {
    if vm_ptr.is_null() || reg_name.is_null() || buffer.is_null() {
        return -1;
    }
    
    let vm = unsafe { &mut *vm_ptr };
    let c_str = unsafe { CStr::from_ptr(reg_name) };
    let name = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return -1, // Invalid UTF-8
    };

    match reg_find(vm, name) {
        Ok(reg) => {
            let reg_size = reg.var.size as usize;
            // Ensure the provided buffer size matches the register size
            if buffer_size != reg_size {
                return -1; // Buffer size mismatch
            }

            // Create a slice from the provided buffer
            let input_bytes = unsafe { std::slice::from_raw_parts(buffer, buffer_size) };
            
            // Get mutable access to the register's bytes
            if let Some(reg_bytes) = vm.vm.cpu.regs.get_mut(reg.var) {
                // Check length just in case
                if reg_bytes.len() != reg_size {
                    eprintln!("Warning: Register size mismatch for {}", name);
                    return -1;
                }
                
                // Copy the bytes from the input buffer to the register
                reg_bytes.copy_from_slice(input_bytes);
                0 // Success
            } else {
                -1 // Should not happen if reg_find succeeded, but handle defensively
            }
        }
        Err(_) => -1, // Register not found
    }
}

#[no_mangle]
pub extern "C" fn icicle_breakpoint_list(vm_ptr: *mut Icicle, out_count: *mut usize) -> *mut u64 {
    if vm_ptr.is_null() || out_count.is_null() {
        return ptr::null_mut();
    }
    let vm = unsafe { &*vm_ptr };

    // Get the breakpoints from the Vm's CodeCache
    let breakpoints: Vec<u64> = vm.vm.code.breakpoints.iter().cloned().collect();
    
    if breakpoints.is_empty() {
        unsafe { *out_count = 0 };
        return ptr::null_mut();
    }
    
    unsafe { *out_count = breakpoints.len() };
    
    // Convert the Vec<u64> into a raw pointer for C
    let boxed_slice = breakpoints.into_boxed_slice();
    Box::into_raw(boxed_slice) as *mut u64
}

#[no_mangle]
pub extern "C" fn icicle_breakpoint_list_free(list: *mut u64, count: usize) {
    if list.is_null() || count == 0 {
        return;
    }
    unsafe {
        let slice = std::slice::from_raw_parts_mut(list, count);
        let _ = Box::from_raw(slice as *mut [u64]);
    }
}

// Helper function to map underlying permission bits back to our MemoryProtection enum.
fn perm_to_protection(perm: u8) -> MemoryProtection {
    let read = (perm & perm::READ) != 0;
    let write = (perm & perm::WRITE) != 0;
    let exec = (perm & perm::EXEC) != 0;

    match (read, write, exec) {
        (true, true, true) => MemoryProtection::ExecuteReadWrite,
        (true, true, false) => MemoryProtection::ReadWrite,
        (true, false, true) => MemoryProtection::ExecuteRead,
        (true, false, false) => MemoryProtection::ReadOnly,
        (false, false, true) => MemoryProtection::ExecuteOnly,
        _ => MemoryProtection::NoAccess,
    }
}

// ----- C-compatible struct for memory region info -----
#[repr(C)]
pub struct MemRegionInfo {
    pub address: u64,
    pub size: u64,
    pub protection: MemoryProtection,
}

/// Retrieves a list of physically mapped memory regions in the VM.
///
/// @param vm_ptr Pointer to the Icicle VM instance.
/// @param out_count Pointer to a size_t where the number of mapped regions will be stored.
/// @return A pointer to an array of MemRegionInfo structs. The caller is responsible
///         for freeing this array using icicle_mem_list_mapped_free().
///         Returns NULL on failure or if no regions are mapped.
#[no_mangle]
pub extern "C" fn icicle_mem_list_mapped(vm_ptr: *mut Icicle, out_count: *mut usize) -> *mut MemRegionInfo {
    if vm_ptr.is_null() || out_count.is_null() {
        // Ensure out_count is initialized even on early failure
        if !out_count.is_null() { unsafe { *out_count = 0 }; }
        return ptr::null_mut();
    }
    let vm = unsafe { &*vm_ptr };
    let mapping = vm.vm.cpu.mem.get_mapping();

    // Iterate through the blocks reported by the mapping iterator
    // Then scan within each block to find contiguous mapped regions
    let mut regions = Vec::new();
    let mut next_scan_start = 0_u64; // Track the next address to start scanning from

    for (block_start, block_len, _entry) in mapping.iter() {

        // Skip this block entirely if we've already scanned past its beginning
        if block_start < next_scan_start {
            continue;
        }

        let block_end = match block_start.checked_add(block_len) {
            Some(end) => end,
            None => u64::MAX, // Handle potential overflow for block end
        };

        // Start scanning from where we left off, or the block start, whichever is greater
        let mut current_addr = std::cmp::max(block_start, next_scan_start);

        while current_addr < block_end {
            let current_perm = vm.vm.cpu.mem.get_perm(current_addr);

            if current_perm != perm::NONE {
                // Found the start of an actually mapped region
                let region_start = current_addr;
                let mut region_end = region_start;

                // Scan forward within the block to find the end of contiguous permissions
                loop {
                    // Check next address, carefully handling potential overflow and block boundary
                    let next_addr = match region_end.checked_add(1) {
                        Some(addr) if addr < block_end => addr,
                        _ => break, // Reached end of block or u64::MAX
                    };

                    if vm.vm.cpu.mem.get_perm(next_addr) == current_perm {
                        region_end = next_addr; // Extend region
                    } else {
                        break; // Permission changed
                    }
                }

                let region_size = region_end - region_start + 1;
                regions.push(MemRegionInfo {
                    address: region_start,
                    size: region_size,
                    protection: perm_to_protection(current_perm),
                });

                // Update next_scan_start to the address AFTER the detected region
                next_scan_start = match region_end.checked_add(1) {
                     Some(addr) => addr,
                     None => u64::MAX, // Reached end of address space
                };
                current_addr = next_scan_start; // Continue inner scan from the next address

                if current_addr == u64::MAX || current_addr >= block_end { 
                    break; // Exit inner loop if wrapped or passed block end
                }

            } else {
                // Address is unmapped, advance to the next address within the block
                 current_addr = match current_addr.checked_add(1) {
                    Some(addr) if addr < block_end => addr,
                    _ => break, // Reached end of block or u64::MAX
                 };
                 // Keep next_scan_start updated even when skipping unmapped ranges
                 next_scan_start = std::cmp::max(next_scan_start, current_addr);
            }
        }
        // Ensure next_scan_start reflects progress made in this block
        // (handles cases where inner loop finishes exactly at block_end)
        next_scan_start = std::cmp::max(next_scan_start, current_addr);

        if next_scan_start == u64::MAX { break; } // Exit outer loop if we wrapped around
    }

    /* --- Code to return the collected regions --- */
    if regions.is_empty() {
        unsafe { *out_count = 0 };
        return ptr::null_mut();
    }

    unsafe { *out_count = regions.len() };
    let boxed_slice = regions.into_boxed_slice();
    Box::into_raw(boxed_slice) as *mut MemRegionInfo
}

/// Frees the memory allocated for the memory region list returned by icicle_mem_list_mapped.
///
/// @param list Pointer to the MemRegionInfo array.
/// @param count The number of elements in the list (returned by icicle_mem_list_mapped).
#[no_mangle]
pub extern "C" fn icicle_mem_list_mapped_free(list: *mut MemRegionInfo, count: usize) {
    if list.is_null() || count == 0 {
        return;
    }
    unsafe {
        let slice = std::slice::from_raw_parts_mut(list, count);
        let _ = Box::from_raw(slice as *mut [MemRegionInfo]);
    }
}

// ----- CPU State Serialization/Deserialization -----

// Structure to hold serializable memory region information
#[derive(Serialize, Deserialize, Clone)]
struct SerializedMemoryRegion {
    address: u64,
    size: u64,
    protection: u8, // Using raw protection value for consistency
    content: Vec<u8>,
}

// Structure to hold serializable VM state (CPU + memory)
#[derive(Serialize, Deserialize, Clone)]
struct SerializableVmState {
    // CPU state
    regs_data: Vec<u8>,
    shadow_stack_entries: Vec<(u64, u64)>, // (addr, block)
    exception_code: u32,
    exception_value: u64,
    icount: u64,
    
    // Memory regions
    memory_regions: Vec<SerializedMemoryRegion>,
    // Serialization version for forward/backward compatibility
    version: u32,
}

impl SerializableVmState {
    // Version for serialization format
    const CURRENT_VERSION: u32 = 1;
    // Magic signature for compressed data
    const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD]; // Standard zstd magic number
    
    // Create a serializable state from CPU and memory
    fn from_vm(vm: &Icicle) -> Self {
        // Get CPU state
        let cpu = &vm.vm.cpu;
        
        // Capture register data
        let regs = cpu.regs.clone();
        let regs_data = unsafe { 
            std::slice::from_raw_parts(
                &regs as *const Regs as *const u8,
                std::mem::size_of::<Regs>()
            ).to_vec()
        };

        // Extract shadow stack entries
        let shadow_stack_entries = if cpu.shadow_stack.depth() > 0 {
            cpu.shadow_stack.as_slice()
                .iter()
                .map(|entry| {
                    (entry.addr, entry.block)
                })
                .collect()
        } else {
            Vec::new()
        };

        // Capture CPU exception and icount
        let exception_code = cpu.exception.code;
        let exception_value = cpu.exception.value;
        let icount = cpu.icount;

        // Capture memory regions
        let mut memory_regions = Vec::new();
        let mut region_count: usize = 0;
        
        // Use existing function to get mapped memory regions
        let regions_ptr = unsafe { icicle_mem_list_mapped(vm as *const _ as *mut Icicle, &mut region_count as *mut usize) };
        
        if !regions_ptr.is_null() && region_count > 0 {
            let regions = unsafe { std::slice::from_raw_parts(regions_ptr, region_count) };
            
            // For each region, capture metadata and content
            for region in regions {
                // Skip regions that are too large (optional safety check)
                if region.size > 1024 * 1024 * 100 { // 100 MB limit per region
                    tracing::warn!("Skipping very large memory region at 0x{:x} (size: {} bytes)", 
                                  region.address, region.size);
                    continue;
                }
                
                // Read memory content
                let mut content = Vec::new();
                let size = region.size as usize;
                
                // Read the memory region content
                let mut content_size: usize = 0;
                let content_ptr = unsafe { 
                    icicle_mem_read(
                        vm as *const _ as *mut Icicle, 
                        region.address, 
                        size, 
                        &mut content_size as *mut usize
                    ) 
                };
                
                if !content_ptr.is_null() && content_size > 0 {
                    content = unsafe { 
                        let slice = std::slice::from_raw_parts(content_ptr, content_size);
                        slice.to_vec() 
                    };
                    
                    // Free the buffer allocated by icicle_mem_read
                    unsafe { icicle_free_buffer(content_ptr, content_size) };
                }
                
                // Convert protection to numeric value
                let protection = convert_protection(region.protection);
                
                // Add region to the list
                memory_regions.push(SerializedMemoryRegion {
                    address: region.address,
                    size: region.size,
                    protection,
                    content,
                });
            }
            
            // Free the regions list
            unsafe { icicle_mem_list_mapped_free(regions_ptr, region_count) };
        }
        
        SerializableVmState {
            regs_data,
            shadow_stack_entries,
            exception_code,
            exception_value,
            icount,
            memory_regions,
            version: Self::CURRENT_VERSION,
        }
    }

    // Apply the serialized state to a VM
    fn apply_to_vm(&self, vm: &mut Icicle) -> Result<(), String> {
        // Check version compatibility
        if self.version > Self::CURRENT_VERSION {
            return Err(format!("Unsupported serialization version: {}", self.version));
        }
        
        // Apply CPU state
        let cpu = &mut vm.vm.cpu;
        
        // Apply register data
        if self.regs_data.len() == std::mem::size_of::<Regs>() {
            unsafe {
                let regs_ptr = self.regs_data.as_ptr() as *const Regs;
                cpu.regs = (*regs_ptr).clone();
            }
        } else {
            return Err(format!("Invalid register data size: {}", self.regs_data.len()));
        }

        // Reset and rebuild shadow stack
        let stack_depth = cpu.shadow_stack.depth();
        for _ in 0..stack_depth {
            cpu.pop_shadow_stack(0);
        }
        
        for &(addr, _) in &self.shadow_stack_entries {
            cpu.push_shadow_stack(addr);
        }
        
        // Apply exception data
        cpu.exception.code = self.exception_code;
        cpu.exception.value = self.exception_value;
        
        // Apply instruction count
        cpu.icount = self.icount;
        
        // Apply memory regions
        for region in &self.memory_regions {
            // Check if memory is already mapped at the right address
            let result = vm.mem_map(region.address, region.size, perm_to_protection(region.protection));
            
            // If mapping fails but it's already mapped, try to unmap and remap
            if result.is_err() {
                let _ = vm.mem_unmap(region.address, region.size);
                let _ = vm.mem_map(region.address, region.size, perm_to_protection(region.protection));
            }
            
            // Now write the content if available
            if !region.content.is_empty() {
                if let Err(e) = vm.mem_write(region.address, &region.content) {
                    return Err(format!("Failed to write memory content at 0x{:x}: {}", region.address, e));
                }
            }
        }
        
        Ok(())
    }

    // Serialize to binary
    fn serialize(&self) -> Result<Vec<u8>, String> {
        // Default to no compression
        self.serialize_with_options(false, 0)
    }
    
    // Serialize with compression options
    fn serialize_with_options(&self, compress: bool, compression_level: i32) -> Result<Vec<u8>, String> {
        // First serialize with bincode
        let raw_data = bincode::serialize(self)
            .map_err(|e| format!("Serialization error: {}", e))?;
        
        // If compression is enabled, compress the data
        if compress {
            // Ensure compression level is within valid range (1-22 for zstd)
            let level = if compression_level <= 0 {
                3 // Default compression level
            } else if compression_level > 22 {
                22 // Max compression level
            } else {
                compression_level
            };
            
            // Compress the data
            match zstd::encode_all(&raw_data[..], level) {
                Ok(compressed) => {
                    // Return compressed data with a header to identify it
                    let mut result = Vec::with_capacity(compressed.len() + 4);
                    result.extend_from_slice(&Self::ZSTD_MAGIC);
                    result.extend_from_slice(&compressed);
                    Ok(result)
                },
                Err(_) => {
                    Ok(raw_data)
                }
            }
        } else {
            // Return raw data
            Ok(raw_data)
        }
    }

    // Deserialize from binary
    fn deserialize(data: &[u8]) -> Result<Self, String> {
        // Default to allow decompression
        Self::deserialize_with_options(data, true)
    }
    
    // Deserialize with options
    fn deserialize_with_options(data: &[u8], allow_decompression: bool) -> Result<Self, String> {
        // Check if data is compressed (has zstd magic number)
        if allow_decompression && data.len() > 4 && data[0..4] == Self::ZSTD_MAGIC {
            // Decompress the data
            match zstd::decode_all(&data[4..]) {
                Ok(decompressed) => {
                    // Deserialize the decompressed data
                    bincode::deserialize(&decompressed)
                        .map_err(|e| format!("Deserialization error: {}", e))
                },
                Err(e) => Err(format!("Decompression error: {}", e))
            }
        } else {
            // Data is not compressed or decompression not allowed, deserialize directly
            bincode::deserialize(data)
                .map_err(|e| format!("Deserialization error: {}", e))
        }
    }
}

// ----- FFI Functions for Serialization/Deserialization -----

// Define the log level constants
const LOG_NONE: i32 = 0;
const LOG_ERRORS: i32 = 1;
const LOG_VERBOSE: i32 = 2;

#[no_mangle]
pub extern "C" fn icicle_serialize_vm_state(
    vm_ptr: *mut Icicle,
    filename: *const c_char,
    include_memory: bool,
    log_level: c_int
) -> c_int {
    if vm_ptr.is_null() || filename.is_null() {
        return -1;
    }
    
    let vm = unsafe { &mut *vm_ptr };
    let filename_cstr = unsafe { CStr::from_ptr(filename) };
    let filename_str = match filename_cstr.to_str() {
        Ok(s) => s,
        Err(_) => {
            return -1;
        }
    };
    
    // Get the VM state
    let vm_state = SerializableVmState::from_vm(vm);
    
    // If we don't want to include memory, create a copy without memory regions
    let serialized_data = if include_memory {
        // Determine whether to compress and at what level based on log_level
        // For simplicity: if log_level > 2, enable compression with level = log_level - 2
        let use_compression = log_level > 2;
        let compression_level = log_level - 2;
        
        match vm_state.serialize_with_options(use_compression, compression_level) {
            Ok(data) => data,
            Err(_) => {
                return -1;
            }
        }
    } else {
        // Create a copy without memory regions
        let cpu_only_state = SerializableVmState {
            regs_data: vm_state.regs_data,
            shadow_stack_entries: vm_state.shadow_stack_entries,
            exception_code: vm_state.exception_code,
            exception_value: vm_state.exception_value,
            icount: vm_state.icount,
            memory_regions: Vec::new(),
            version: vm_state.version,
        };
        
        // For CPU-only, use compression if log_level > 2
        let use_compression = log_level > 2;
        let compression_level = log_level - 2;
        
        match cpu_only_state.serialize_with_options(use_compression, compression_level) {
            Ok(data) => data,
            Err(_) => {
                return -1;
            }
        }
    };
    
    // Write to file
    match std::fs::write(filename_str, &serialized_data) {
        Ok(_) => {
            0 // Success
        }
        Err(_) => {
            -1 // Error
        }
    }
}

#[no_mangle]
pub extern "C" fn icicle_deserialize_vm_state(
    vm_ptr: *mut Icicle,
    filename: *const c_char,
    apply_memory: bool,
    log_level: c_int
) -> c_int {
    if vm_ptr.is_null() || filename.is_null() {
        return -1;
    }
    
    let vm = unsafe { &mut *vm_ptr };
    let filename_cstr = unsafe { CStr::from_ptr(filename) };
    let filename_str = match filename_cstr.to_str() {
        Ok(s) => s,
        Err(_) => {
            return -1;
        }
    };

    // Read from file
    let serialized_data = match std::fs::read(filename_str) {
        Ok(data) => data,
        Err(_) => {
            return -1;
        }
    };
    
    // Deserialize the VM state with decompression enabled
    let mut vm_state = match SerializableVmState::deserialize_with_options(&serialized_data, true) {
        Ok(state) => state,
        Err(_) => {
            return -1;
        }
    };
    
    // If we don't want to apply memory, clear the memory regions
    if !apply_memory {
        vm_state.memory_regions.clear();
    }

    // Apply the VM state
    match vm_state.apply_to_vm(vm) {
        Ok(_) => {
            0 // Success
        },
        Err(_) => {
            -1 // Error
        }
    }
}

// For backwards compatibility
#[no_mangle]
pub extern "C" fn icicle_serialize_cpu_state(
    vm_ptr: *mut Icicle,
    filename: *const c_char,
    log_level: c_int
) -> c_int {
    // Call the new function with include_memory=false
    icicle_serialize_vm_state(vm_ptr, filename, false, log_level)
}

#[no_mangle]
pub extern "C" fn icicle_deserialize_cpu_state(
    vm_ptr: *mut Icicle,
    filename: *const c_char,
    log_level: c_int
) -> c_int {
    // Call the new function with apply_memory=false
    icicle_deserialize_vm_state(vm_ptr, filename, false, log_level)
}

// Function to get the size of serialized data (useful for pre-allocating buffers)
#[no_mangle]
pub extern "C" fn icicle_get_serialized_size(vm_ptr: *mut Icicle) -> usize {
    if vm_ptr.is_null() {
        return 0;
    }
    
    let vm = unsafe { &mut *vm_ptr };
    
    // Create serializable state (CPU only for compatibility)
    let vm_state = SerializableVmState::from_vm(vm);
    let cpu_only_state = SerializableVmState {
        regs_data: vm_state.regs_data,
        shadow_stack_entries: vm_state.shadow_stack_entries,
        exception_code: vm_state.exception_code,
        exception_value: vm_state.exception_value,
        icount: vm_state.icount,
        memory_regions: Vec::new(),
        version: vm_state.version,
    };
    
    // Serialize to get size
    match cpu_only_state.serialize() {
        Ok(data) => data.len(),
        Err(_) => 0,
    }
}

// Get the estimated size with memory included
#[no_mangle]
pub extern "C" fn icicle_get_vm_serialized_size(vm_ptr: *mut Icicle) -> usize {
    if vm_ptr.is_null() {
        return 0;
    }
    
    let vm = unsafe { &mut *vm_ptr };
    
    // Create full serializable state
    let vm_state = SerializableVmState::from_vm(vm);
    
    // Serialize to get size
    match vm_state.serialize() {
        Ok(data) => data.len(),
        Err(_) => 0,
    }
}