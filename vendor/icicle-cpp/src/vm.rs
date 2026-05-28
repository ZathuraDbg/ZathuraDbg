// Icicle VM struct and core methods.

use std::collections::HashMap;
use std::os::raw::c_void;
use icicle_cpu::mem::{Mapping, perm, ReadAfterHook, WriteHook};
use icicle_cpu::{Cpu, ValueSource, VmExit, ExceptionCode};
use target_lexicon::Architecture;
use sleigh_runtime::NamedRegister;

use crate::types::{
    convert_protection, CoverageMode, MemoryProtection, RunStatus, SyscallHookFunction, SyscallArgs, ViolationFunction,
};
struct X86FlagsRegHandler {
    pub eflags: pcode::VarNode,
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

// ----- The Icicle VM structure -----
pub struct Icicle {
    #[allow(dead_code)]
    pub(crate) architecture: String,
    pub(crate) vm: icicle_vm::Vm,
    pub(crate) regs: HashMap<String, NamedRegister>,
    pub(crate) violation_callback: Option<(ViolationFunction, *mut c_void)>,
    pub(crate) syscall_callback: Option<(SyscallHookFunction, *mut c_void)>,
    pub(crate) mem_read_hooks: HashMap<u32, Box<dyn ReadAfterHook>>,
    pub(crate) mem_write_hooks: HashMap<u32, Box<dyn WriteHook>>,
    pub(crate) next_mem_hook_id: u32,
    pub(crate) execution_hooks: HashMap<u32, Box<dyn FnMut(&mut Cpu, u64)>>,
    pub(crate) next_execution_hook_id: u32,
    pub(crate) coverage_mode: CoverageMode,
    pub(crate) coverage_start_addr: u64,
    pub(crate) coverage_end_addr: u64,
    pub(crate) context_bits: u8,
    pub(crate) compcov_level: u8,
    pub(crate) instrumentation_enabled: bool,
    pub(crate) coverage_map: Vec<u8>,
    pub(crate) coverage_hook_id: Option<u32>,
}

impl Icicle {
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
        if config.triple.architecture == Architecture::Unknown {
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
                let eflags = sleigh.get_reg("eflags").unwrap().get_raw_var();
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
            next_mem_hook_id: 1,
            execution_hooks: HashMap::new(),
            next_execution_hook_id: 3,
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

    pub fn get_icount_limit(&self) -> u64 { self.vm.icount_limit }
    pub fn set_icount_limit(&mut self, value: u64) { self.vm.icount_limit = value; }
    pub fn get_icount(&self) -> u64 { self.vm.cpu.icount }
    pub fn set_icount(&mut self, value: u64) { self.vm.cpu.icount = value; }
    pub fn get_pc(&self) -> u64 { self.vm.cpu.read_pc() }
    pub fn set_pc(&mut self, address: u64) { self.vm.cpu.write_pc(address) }

    pub fn get_sp(&mut self) -> u64 {
        self.vm.cpu.read_reg(self.vm.cpu.arch.reg_sp)
    }
    pub fn set_sp(&mut self, address: u64) {
        self.vm.cpu.write_reg(self.vm.cpu.arch.reg_sp, address)
    }
    pub fn get_mem_capacity(&self) -> usize { self.vm.cpu.mem.capacity() }

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

    pub fn reset(&mut self) { self.vm.reset(); }

    pub fn run(&mut self) -> RunStatus {
        const X86_64_SYSCALL_INSN_LEN: u64 = 2;
        const X86_64_NULL_WRITE_INSN_LEN: u64 = 6;
        const SYS_EXIT_NR: u64 = 0x3C;

        loop {
            match self.vm.run() {
                VmExit::UnhandledException(_) => {
                    let code = self.vm.cpu.exception.code;
                    let value = self.vm.cpu.exception.value;
                    let is_syscall = code == ExceptionCode::Syscall as u32;
                    let is_violation = !is_syscall
                        && matches!(
                            code,
                            c if c == ExceptionCode::ReadUnmapped as u32
                                || c == ExceptionCode::WriteUnmapped as u32
                                || c == ExceptionCode::ReadPerm as u32
                                || c == ExceptionCode::WritePerm as u32
                                || c == ExceptionCode::ExecViolation as u32
                        );

                    if is_violation && self.violation_callback.is_some() {
                        let (callback, data) = *self.violation_callback.as_ref().unwrap();
                        let address = value;
                        let unmapped = (code == ExceptionCode::ReadUnmapped as u32
                            || code == ExceptionCode::WriteUnmapped as u32)
                            as std::os::raw::c_int;
                        let permission = match code {
                            c if c == ExceptionCode::ReadPerm as u32
                                || c == ExceptionCode::ReadUnmapped as u32 => perm::READ,
                            c if c == ExceptionCode::WritePerm as u32
                                || c == ExceptionCode::WriteUnmapped as u32 => perm::WRITE,
                            c if c == ExceptionCode::ExecViolation as u32 => perm::EXEC,
                            _ => 0,
                        };

                        if (callback)(data, address, permission, unmapped) == 0 {
                            return RunStatus::UnhandledException;
                        }

                        if address == 0
                            && (code == ExceptionCode::WriteUnmapped as u32
                                || code == ExceptionCode::WritePerm as u32)
                        {
                            let pc = self.vm.cpu.read_pc();
                            self.vm.cpu.write_pc(pc + X86_64_NULL_WRITE_INSN_LEN);
                        }
                        self.vm.cpu.exception.clear();
                        continue;
                    }

                    if is_syscall && self.syscall_callback.is_some() {
                        // The syscall callback path below is x86-64-specific:
                        // it reads RAX, RDI, RSI, etc. and advances PC by 2
                        // (the length of `syscall` on x86-64).  On other
                        // architectures the syscall exception fires but the
                        // handler cannot safely interpret it, so we let it
                        // propagate as an unhandled exception.
                        if self.architecture != "x86_64" {
                            return RunStatus::UnhandledException;
                        }
                        let (callback, data) = *self.syscall_callback.as_ref().unwrap();
                        let cpu = &mut self.vm.cpu;
                        let syscall_nr = cpu.arch.sleigh
                            .get_reg("RAX")
                            .and_then(|r| r.get_var())
                            .map(|v| cpu.read_reg(v))
                            .unwrap_or(u64::MAX);
                        let args = SyscallArgs {
                            arg0: cpu.arch.sleigh.get_reg("RDI").and_then(|r| r.get_var()).map(|v| cpu.read_reg(v)).unwrap_or(0),
                            arg1: cpu.arch.sleigh.get_reg("RSI").and_then(|r| r.get_var()).map(|v| cpu.read_reg(v)).unwrap_or(0),
                            arg2: cpu.arch.sleigh.get_reg("RDX").and_then(|r| r.get_var()).map(|v| cpu.read_reg(v)).unwrap_or(0),
                            arg3: cpu.arch.sleigh.get_reg("R10").and_then(|r| r.get_var()).map(|v| cpu.read_reg(v)).unwrap_or(0),
                            arg4: cpu.arch.sleigh.get_reg("R8").and_then(|r| r.get_var()).map(|v| cpu.read_reg(v)).unwrap_or(0),
                            arg5: cpu.arch.sleigh.get_reg("R9").and_then(|r| r.get_var()).map(|v| cpu.read_reg(v)).unwrap_or(0),
                        };

                        match (callback)(data, syscall_nr, &args as *const SyscallArgs) {
                            0 if syscall_nr == SYS_EXIT_NR => {
                                cpu.exception.clear();
                                return RunStatus::Halt;
                            }
                            0 | 1 => {
                                let pc = cpu.read_pc();
                                cpu.write_pc(pc + X86_64_SYSCALL_INSN_LEN);
                                cpu.exception.clear();
                                continue;
                            }
                            _ => return RunStatus::UnhandledException,
                        }
                    }

                    return RunStatus::UnhandledException;
                }
                other => return vm_exit_to_run_status(other),
            }
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

    pub fn step_back(&mut self, count: u64) -> Option<RunStatus> {
        self.vm.step_back(count).map(vm_exit_to_run_status)
    }

    pub fn goto_icount(&mut self, target_icount: u64) -> Option<RunStatus> {
        self.vm.goto_icount(target_icount).map(vm_exit_to_run_status)
    }

    pub fn save_snapshot(&mut self) {
        self.vm.save_snapshot();
    }
}

pub(crate) fn vm_exit_to_run_status(exit: VmExit) -> RunStatus {
    match exit {
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
    }
}

pub(crate) fn reg_find<'a>(i: &'a Icicle, name: &str) -> Result<&'a NamedRegister, String> {
    let sleigh = &i.vm.cpu.arch.sleigh;
    match sleigh.get_reg(name) {
        None => {
            i.regs.get(&name.to_lowercase())
                .ok_or(format!("Register not found: {}", name))
        }
        Some(r) => Ok(r),
    }
}
