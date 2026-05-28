use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uchar, c_void};
use std::ptr;
use icicle_cpu::mem::{Mapping, perm, Mmu, ReadAfterHook, WriteHook};
use icicle_cpu::{Cpu, VmExit, Regs, ShadowStack, Exception};
use icicle_vm::cpu::{Environment, debug_info::{DebugInfo, SourceLocation}};
use icicle_vm::cpu::mem::AllocLayout;
use serde::{Serialize, Deserialize};

mod types;
mod vm;

use crate::types::*;
use crate::vm::{Icicle, reg_find};

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
    // Note: we cannot remove a hook from the core VM's hook list (the upstream
    // API doesn't expose hook-removal), so the hook stays active in the VM but
    // its closure is dropped, making it a no-op.
    vm.execution_hooks.remove(&hook_id);
    0
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

/// Legacy function to maintain compatibility with existing code.
/// The hook_id parameter is ignored — there is exactly one syscall hook
/// (ID 2) and this always removes it.
#[no_mangle]
pub extern "C" fn icicle_remove_syscall_hook(vm_ptr: *mut Icicle, _hook_id: u32) -> c_int {
    icicle_remove_hook(vm_ptr, 2)
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
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn icicle_free(ptr: *mut Icicle) {
    if !ptr.is_null() {
        unsafe { drop(Box::from_raw(ptr)); }
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
        Err(_) => -1,
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
        Err(_) => -1,
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
        Err(_) => -1,
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
        Err(_) => std::ptr::null_mut(),
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
        Err(_) => -1,
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
            let value = vm.vm.cpu.read_reg(reg.get_raw_var());
            unsafe { *out_value = value; }
            0
        }
        Err(_) => -1,
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
            if reg.get_raw_var() == vm.vm.cpu.arch.reg_pc {
                vm.vm.cpu.write_pc(value);
            } else {
                vm.vm.cpu.write_reg(reg.get_raw_var(), value);
            }
            0
        }
        Err(_) => -1,
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
            size: reg.get_raw_var().size,
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
        Ok(reg) => reg.get_raw_var().size as c_int,
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
        Err(_) => -1,
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

pub struct RawEnvironment {
    debug_info: DebugInfo,
}

impl RawEnvironment {
    pub fn new() -> Self {
        Self { debug_info: DebugInfo::default() }
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
        unsafe { drop(Box::from_raw(env)); }
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
        Err(_) => -1,
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

    let wrapper = ReadHookWrapper { callback, user_data: data };

    match vm.vm.cpu.mem.add_read_after_hook(start_addr, end_addr, Box::new(wrapper.clone())) {
        Some(_) => {
            let hook_id = vm.next_mem_hook_id;
            vm.next_mem_hook_id += 1;
            vm.mem_read_hooks.insert(hook_id, Box::new(wrapper));
            hook_id
        }
        None => 0,
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

    let wrapper = WriteHookWrapper { callback, user_data: data };

    match vm.vm.cpu.mem.add_write_hook(start_addr, end_addr, Box::new(wrapper.clone())) {
        Some(_) => {
            let hook_id = vm.next_mem_hook_id;
            vm.next_mem_hook_id += 1;
            vm.mem_write_hooks.insert(hook_id, Box::new(wrapper));
            hook_id
        }
        None => 0,
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
            drop(Box::from_raw(snapshot.regs));
            drop(Box::from_raw(snapshot.shadow_stack));
            drop(Box::from_raw(snapshot.pending_exception));
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
            drop(Box::from_raw(snapshot.mem));
            drop(Box::from_raw(snapshot.env));
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
                Some(reg) => reg.get_raw_var(),
                None => continue,
            };
            
            let value = cpu.read_reg(var);
            reg_values.push(value);
            c_reg_names.push(reg_name.as_ptr());
        }
        
        // Call the C callback
        if !c_reg_names.is_empty() {
            (reg_hook.callback)(
                reg_hook.user_data,
                reg_hook.name.as_ptr(),
                addr,
                c_reg_names.len(),
                c_reg_names.as_ptr(),
                reg_values.as_ptr(),
            );
        }
    };
    
    // Add hook to VM
    let hook_id = vm.next_execution_hook_id;
    vm.next_execution_hook_id += 1;
    
    // Add execution hook to the VM
    let internal_hook_id = vm.vm.cpu.add_hook(Box::new(hook_fn.clone()));
    // Register to activate the hook at the specific instruction address.
    // Instruction-level injection is more precise than block-level for
    // single-address hooks, especially when the address is a jmp target.
    icicle_vm::injector::register_instruction_hook_injector(&mut vm.vm, vec![address], internal_hook_id);
    
    // Store for future reference
    vm.execution_hooks.insert(hook_id, Box::new(hook_fn));
    
    hook_id
}

// Default debug hook that will be used if environment variable configuration is used
extern "C" fn default_log_write_hook(_data: *mut c_void, name: *const c_char, address: u64, size: u8, value: u64) {
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
extern "C" fn default_log_regs_hook(_data: *mut c_void, name: *const c_char, address: u64, num_regs: usize, reg_names: *const *const c_char, reg_values: *const u64) {
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
    
    // Resize the existing coverage map in-place rather than allocating a new
    // Vec. This avoids invalidating the raw pointer held by any still-registered
    // coverage hooks (a known upstream limitation: hooks cannot be removed from
    // the core VM).  If the size stays the same, the internal buffer is reused
    // and existing hooks continue to write to valid memory.
    let size = match mode {
        CoverageMode::Blocks | CoverageMode::Edges => 4096,
        CoverageMode::BlockCounts | CoverageMode::EdgeCounts => 4096 * 2,
    };
    vm.coverage_map.clear();
    vm.coverage_map.resize(size, 0);
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

// Returns a fresh boxed coverage hook for `mode` that writes into the Vec<u8>
// behind `coverage_map_ptr`. The caller is responsible for ensuring the pointer
// outlives the hook (in practice it points into the Icicle struct, which lives
// as long as the FFI handle).
fn build_coverage_hook(
    coverage_map_ptr: *mut Vec<u8>,
    mode: CoverageMode,
) -> Box<dyn FnMut(&mut Cpu, u64)> {
    // SAFETY: coverage_map_ptr is the only mutable alias kept on the coverage
    // map for the lifetime of this hook; the VM invokes hooks single-threaded
    // and the Vec is reallocated only when coverage is reset (which removes
    // and replaces the hook beforehand).
    match mode {
        CoverageMode::Blocks => Box::new(move |_cpu: &mut Cpu, pc: u64| {
            let map = unsafe { &mut *coverage_map_ptr };
            mark_bit(map, pc as usize);
        }),
        CoverageMode::Edges => {
            let mut prev_pc = 0u64;
            Box::new(move |_cpu: &mut Cpu, pc: u64| {
                let map = unsafe { &mut *coverage_map_ptr };
                let edge_hash = ((prev_pc >> 4) ^ pc) as usize;
                mark_bit(map, edge_hash);
                prev_pc = pc;
            })
        }
        CoverageMode::BlockCounts => Box::new(move |_cpu: &mut Cpu, pc: u64| {
            let map = unsafe { &mut *coverage_map_ptr };
            inc_counter(map, pc as usize);
        }),
        CoverageMode::EdgeCounts => {
            let mut prev_pc = 0u64;
            Box::new(move |_cpu: &mut Cpu, pc: u64| {
                let map = unsafe { &mut *coverage_map_ptr };
                let edge_hash = ((prev_pc >> 4) ^ pc) as usize;
                inc_counter(map, edge_hash);
                prev_pc = pc;
            })
        }
    }
}

// Sets a single coverage bit at the given hash index in a bit-mapped coverage table.
fn mark_bit(map: &mut [u8], hash: usize) {
    if map.is_empty() {
        return;
    }
    let idx = hash % (map.len() * 8);
    let byte_idx = idx / 8;
    let bit_idx = idx % 8;
    if byte_idx < map.len() {
        map[byte_idx] |= 1 << bit_idx;
    }
}

// Increments a saturating u16 counter at the given hash index in a counter-based
// coverage table (2 bytes per slot).
fn inc_counter(map: &mut [u8], hash: usize) {
    if map.len() < 2 {
        return;
    }
    let idx = hash % (map.len() / 2);
    let byte_idx = idx * 2;
    if byte_idx + 1 >= map.len() {
        return;
    }
    let counter = u16::from_le_bytes([map[byte_idx], map[byte_idx + 1]]);
    if counter < u16::MAX {
        let bytes = (counter + 1).to_le_bytes();
        map[byte_idx] = bytes[0];
        map[byte_idx + 1] = bytes[1];
    }
}

// Internal function to add the appropriate coverage hook.
fn add_coverage_hook(vm_ptr: *mut Icicle, mode: CoverageMode) -> u32 {
    let vm = unsafe { &mut *vm_ptr };
    let coverage_map_ptr = &mut vm.coverage_map as *mut Vec<u8>;

    // Register the hook with the core VM.
    let hook_fn = build_coverage_hook(coverage_map_ptr, mode);
    let internal_id = vm.vm.cpu.add_hook(hook_fn);

    // Activate it for the configured address range (default: all addresses).
    let (start, end) = if vm.coverage_start_addr < vm.coverage_end_addr {
        (vm.coverage_start_addr, vm.coverage_end_addr)
    } else {
        (0, u64::MAX)
    };
    icicle_vm::injector::register_block_hook_injector(&mut vm.vm, start, end, internal_id);

    // Store an inert tracking entry so the FFI ID can be allocated/removed.
    // The core VM owns the live closure; the entry in execution_hooks is only
    // used so icicle_remove_execution_hook can recognize this ID. Removing it
    // does NOT deactivate the core hook (a known limitation).
    let ffi_hook_id = vm.next_execution_hook_id;
    vm.next_execution_hook_id += 1;
    vm.execution_hooks
        .insert(ffi_hook_id, Box::new(|_cpu: &mut Cpu, _pc: u64| {}));

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
    if vm_ptr.is_null() || start_addr > end_addr {
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
            let reg_size = reg.get_raw_var().size as usize;
            // Ensure the provided buffer is large enough
            if buffer_size < reg_size {
                return -1; // Buffer too small
            }

            // Read the raw bytes directly from the Regs storage
            if let Some(bytes) = vm.vm.cpu.regs.get(reg.get_raw_var()) {
                 // Check length just in case, though reg.get_raw_var().size should be correct
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
            let reg_size = reg.get_raw_var().size as usize;
            // Ensure the provided buffer size matches the register size
            if buffer_size != reg_size {
                return -1; // Buffer size mismatch
            }

            // Create a slice from the provided buffer
            let input_bytes = unsafe { std::slice::from_raw_parts(buffer, buffer_size) };
            
            // Get mutable access to the register's bytes
            if let Some(reg_bytes) = vm.vm.cpu.regs.get_mut(reg.get_raw_var()) {
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
    
    // Capture the CPU-only portion of the VM state (no memory touched).
    fn cpu_state_from_vm(vm: &Icicle) -> (Vec<u8>, Vec<(u64, u64)>, u32, u64, u64) {
        let cpu = &vm.vm.cpu;
        let regs = cpu.regs.clone();
        // SAFETY: Regs is repr(C) / POD-like; we transmute its byte representation
        // to a Vec<u8>. The same Regs layout must be used at deserialize time.
        let regs_data = unsafe {
            std::slice::from_raw_parts(
                &regs as *const Regs as *const u8,
                std::mem::size_of::<Regs>(),
            ).to_vec()
        };
        let shadow_stack_entries = if cpu.shadow_stack.depth() > 0 {
            cpu.shadow_stack
                .as_slice()
                .iter()
                .map(|entry| (entry.addr, entry.block))
                .collect()
        } else {
            Vec::new()
        };
        (
            regs_data,
            shadow_stack_entries,
            cpu.exception.code,
            cpu.exception.value,
            cpu.icount,
        )
    }

    // Collect mapped regions and their contents for serialization.
    fn collect_memory_regions(vm: &mut Icicle) -> Vec<SerializedMemoryRegion> {
        let mut memory_regions = Vec::new();
        let mut region_count: usize = 0;
        let regions_ptr = icicle_mem_list_mapped(vm, &mut region_count);

        if !regions_ptr.is_null() && region_count > 0 {
            let regions = unsafe { std::slice::from_raw_parts(regions_ptr, region_count) };
            const MAX_REGION_SIZE: u64 = 100 * 1024 * 1024;

            for region in regions {
                if region.size > MAX_REGION_SIZE {
                    tracing::warn!(
                        "Skipping very large memory region at 0x{:x} (size: {} bytes)",
                        region.address, region.size
                    );
                    continue;
                }

                let size = region.size as usize;
                let mut content_size: usize = 0;
                let content_ptr = icicle_mem_read(vm, region.address, size, &mut content_size);

                let content = if !content_ptr.is_null() && content_size > 0 {
                    let bytes = unsafe { std::slice::from_raw_parts(content_ptr, content_size).to_vec() };
                    icicle_free_buffer(content_ptr, content_size);
                    bytes
                } else {
                    Vec::new()
                };

                memory_regions.push(SerializedMemoryRegion {
                    address: region.address,
                    size: region.size,
                    protection: convert_protection(region.protection),
                    content,
                });
            }

            icicle_mem_list_mapped_free(regions_ptr, region_count);
        }

        memory_regions
    }

    // Build the full state (CPU + optionally memory).
    fn from_vm(vm: &mut Icicle, include_memory: bool) -> Self {
        let (regs_data, shadow_stack_entries, exception_code, exception_value, icount) =
            Self::cpu_state_from_vm(vm);
        let memory_regions = if include_memory {
            Self::collect_memory_regions(vm)
        } else {
            Vec::new()
        };

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
    
    let use_compression = log_level > 2;
    let compression_level = log_level - 2;
    let vm_state = SerializableVmState::from_vm(vm, include_memory);

    let serialized_data = match vm_state.serialize_with_options(use_compression, compression_level) {
        Ok(data) => data,
        Err(_) => return -1,
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
    _log_level: c_int,
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
    match SerializableVmState::from_vm(vm, false).serialize() {
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
    match SerializableVmState::from_vm(vm, true).serialize() {
        Ok(data) => data.len(),
        Err(_) => 0,
    }
}