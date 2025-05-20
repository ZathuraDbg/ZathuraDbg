#ifndef ICICLE_FFI_H
#define ICICLE_FFI_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    NoAccess = 0,
    ReadOnly = 1,
    ReadWrite = 2,
    ExecuteOnly = 3,
    ExecuteRead = 4,
    ExecuteReadWrite = 5
} MemoryProtection;

// Coverage modes for instrumentation
typedef enum {
    CoverageMode_Blocks = 0,      // Store a bit whenever a block is hit
    CoverageMode_Edges = 1,       // Store a bit whenever an edge is hit
    CoverageMode_BlockCounts = 2, // Increment a counter whenever a block is hit
    CoverageMode_EdgeCounts = 3   // Increment a counter whenever an edge is hit
} CoverageMode;

typedef enum {
    Running = 0,
    InstructionLimit = 1,
    Breakpoint = 2,
    Interrupted = 3,
    Halt = 4,
    Killed = 5,
    Deadlock = 6,
    OutOfMemory = 7,
    Unimplemented = 8,
    UnhandledException = 9
} RunStatus;

// Exception codes that can be returned by icicle_get_exception_code
typedef enum {
    Exception_NoException = 0,
    Exception_InstructionLimit = 1,
    Exception_Halt = 2,
    Exception_Sleep = 3,
    Exception_Syscall = 4,
    Exception_CpuStateChanged = 5,
    Exception_DivisionException = 6,
    Exception_ReadUnmapped = 7,
    Exception_ReadPerm = 8,
    Exception_ReadUnaligned = 9,
    Exception_ReadWatch = 10,
    Exception_ReadUninitialized = 11,
    Exception_WriteUnmapped = 12,
    Exception_WritePerm = 13,
    Exception_WriteWatch = 14,
    Exception_WriteUnaligned = 15,
    Exception_ExecViolation = 16,
    Exception_SelfModifyingCode = 17,
    Exception_OutOfMemory = 18,
    Exception_AddressOverflow = 19,
    Exception_InvalidInstruction = 20,
    Exception_UnknownInterrupt = 21,
    Exception_UnknownCpuID = 22,
    Exception_InvalidOpSize = 23,
    Exception_InvalidFloatSize = 24,
    Exception_CodeNotTranslated = 25,
    Exception_ShadowStackOverflow = 26,
    Exception_ShadowStackInvalid = 27,
    Exception_InvalidTarget = 28,
    Exception_UnimplementedOp = 29,
    Exception_ExternalAddr = 30,
    Exception_Environment = 31,
    Exception_JitError = 32,
    Exception_InternalError = 33,
    Exception_UnmappedRegister = 34,
    Exception_UnknownError = 35
} IcicleExceptionCode;

typedef struct Icicle Icicle;
typedef struct RawEnvironment RawEnvironment;
// Hook Callback Types
typedef int (*ViolationFunction)(void* data, uint64_t address, uint8_t permission, int unmapped);
typedef void (*RawFunction)(void* data);
typedef void (*PtrFunction)(void* data, uint64_t address);

// Syscall Arguments Structure (for x86_64 Linux convention)
typedef struct {
    uint64_t arg0; // RDI
    uint64_t arg1; // RSI
    uint64_t arg2; // RDX
    uint64_t arg3; // R10
    uint64_t arg4; // R8
    uint64_t arg5; // R9
} SyscallArgs;

// Updated Syscall Hook Callback Type with Context
// Return value semantics: 0=Continue after syscall, 1=Skip syscall, -1=Propagate Exception
typedef int (*SyscallHookFunction)(void* data, uint64_t syscall_nr, const SyscallArgs* args);

typedef struct Cpu Cpu;
struct Cpu;

typedef struct {
    char* name;
    uint32_t offset;
    uint8_t size;
} RegInfo;

// New Memory Hook Callback Types
typedef void (*MemReadHookFunction)(void* data, uint64_t address, uint8_t size, const uint8_t* value_read);
typedef void (*MemWriteHookFunction)(void* data, uint64_t address, uint8_t size, uint64_t value_written);

// New debug instrumentation types
typedef void (*LogWriteHookFunction)(void* data, const char* name, uint64_t address, uint8_t size, uint64_t value);
typedef void (*LogRegsHookFunction)(void* data, const char* name, uint64_t address, size_t num_regs, const char** reg_names, const uint64_t* reg_values);

// CPU Snapshot structure
typedef struct {
    void* regs;  // Opaque pointer to Regs
    __uint128_t args[8];  // Using compiler-specific 128-bit type
    void* shadow_stack;  // Opaque pointer to ShadowStack
    uint32_t exception_code;
    uint64_t exception_value;
    void* pending_exception;  // Optional<Exception>
    uint64_t icount;
    uint64_t block_id;
    uint64_t block_offset;
} CpuSnapshot;

// Full VM snapshot structure
typedef struct {
    CpuSnapshot* cpu;
    void* mem;  // Opaque pointer to memory snapshot
    void* env;  // Opaque pointer to environment snapshot
} VmSnapshot;

// ----- NEW: Structure for Memory Region Information -----
typedef struct {
    uint64_t address;
    uint64_t size;
    MemoryProtection protection;
} MemRegionInfo;

// Snapshot and restore functions
CpuSnapshot* icicle_cpu_snapshot(Icicle* vm);
int icicle_cpu_restore(Icicle* vm, const CpuSnapshot* snapshot);
void icicle_cpu_snapshot_free(CpuSnapshot* snapshot);

// Full VM snapshot functions
VmSnapshot* icicle_vm_snapshot(Icicle* vm);
int icicle_vm_restore(Icicle* vm, const VmSnapshot* snapshot);
void icicle_vm_snapshot_free(VmSnapshot* snapshot);

Icicle* icicle_new(const char *architecture,
                   int jit,
                   int jit_mem,
                   int shadow_stack,
                   int recompilation,
                   int track_uninitialized,
                   int optimize_instructions,
                   int optimize_block,
                   int tracing);
void icicle_free(Icicle* ptr);
uint64_t icicle_get_icount(const Icicle* ptr);
void icicle_set_icount(Icicle* ptr, uint64_t count);
uint64_t icicle_get_pc(const Icicle* ptr);
void icicle_set_pc(Icicle* ptr, uint64_t addr);
void icicle_reset(Icicle* ptr);
RunStatus icicle_run(Icicle* ptr);
RunStatus icicle_step(Icicle* ptr, uint64_t count);
int icicle_mem_map(Icicle* ptr, uint64_t address, uint64_t size, MemoryProtection protection);
int icicle_mem_unmap(Icicle* ptr, uint64_t address, uint64_t size);
int icicle_mem_protect(Icicle* ptr, uint64_t address, size_t size, MemoryProtection protection);
unsigned char* icicle_mem_read(Icicle* ptr, uint64_t address, size_t size, size_t* out_size);
int icicle_mem_write(Icicle* ptr, uint64_t address, const unsigned char* data, size_t size);
void icicle_free_buffer(unsigned char* buffer, size_t size);

// Get the current exception code from the VM's CPU
// Returns NoException if there is no active exception
IcicleExceptionCode icicle_get_exception_code(const Icicle* ptr);

// Utility functions.
uint64_t icicle_get_sp(Icicle* ptr);
void icicle_set_sp(Icicle* ptr, uint64_t addr);
RegInfo* icicle_reg_list(Icicle* ptr, size_t* out_count);
void icicle_reg_list_free(RegInfo* regs, size_t count);
int icicle_reg_size(Icicle* ptr, const char* reg_name);
int icicle_reg_read(Icicle* ptr, const char* reg_name, uint64_t* out_value);
int icicle_reg_write(Icicle* ptr, const char* reg_name, uint64_t value);

/**
 * @brief Reads the raw bytes of a register into a provided buffer.
 *
 * @param ptr Pointer to the Icicle VM instance.
 * @param reg_name The name of the register to read.
 * @param out_buffer Pointer to the buffer where the register bytes will be written.
 * @param buffer_size The size of the provided buffer in bytes.
 * @param out_bytes_read Pointer to a size_t where the actual number of bytes read (the register size) will be stored.
 * @return 0 on success, -1 on failure (e.g., invalid register, buffer too small).
 */
int icicle_reg_read_bytes(Icicle* ptr, const char* reg_name, uint8_t* out_buffer, size_t buffer_size, size_t* out_bytes_read);

/**
 * @brief Writes raw bytes to a register.
 *
 * @param ptr Pointer to the Icicle VM instance.
 * @param reg_name The name of the register to write to.
 * @param buffer Pointer to the buffer containing the bytes to write.
 * @param buffer_size The size of the buffer in bytes.
 * @return 0 on success, -1 on failure (e.g., invalid register, buffer size doesn't match register size).
 */
int icicle_reg_write_bytes(Icicle* ptr, const char* reg_name, const uint8_t* buffer, size_t buffer_size);

size_t icicle_get_mem_capacity(Icicle* ptr);
int icicle_set_mem_capacity(Icicle* ptr, size_t capacity);
bool icicle_add_breakpoint(Icicle* ptr, uint64_t address);
bool icicle_remove_breakpoint(Icicle* ptr, uint64_t address);

/**
 * @brief Retrieves a list of currently set breakpoint addresses.
 *
 * @param ptr Pointer to the Icicle VM instance.
 * @param out_count Pointer to a size_t where the number of breakpoints will be stored.
 * @return A pointer to an array of uint64_t breakpoint addresses. The caller is responsible for freeing this array using icicle_breakpoint_list_free(). Returns NULL on failure or if no breakpoints are set.
 */
uint64_t* icicle_breakpoint_list(Icicle* ptr, size_t* out_count);

/**
 * @brief Frees the memory allocated for the breakpoint list returned by icicle_breakpoint_list.
 *
 * @param list Pointer to the breakpoint list array.
 * @param count The number of elements in the list (returned by icicle_breakpoint_list).
 */
void icicle_breakpoint_list_free(uint64_t* list, size_t count);

RunStatus icicle_run_until(Icicle* ptr, uint64_t address);
RawEnvironment* icicle_rawenv_new();
void icicle_rawenv_free(RawEnvironment* env);
int icicle_rawenv_load(RawEnvironment* env, void* cpu, const unsigned char* code, size_t size);
Cpu* icicle_get_cpu_ptr(Icicle* ptr);
uint32_t icicle_add_violation_hook(Icicle* ptr, ViolationFunction callback, void* data);

// Update add_syscall_hook to use the new callback type
uint32_t icicle_add_syscall_hook(Icicle* ptr, SyscallHookFunction callback, void* data);
uint32_t icicle_add_execution_hook(Icicle* ptr, PtrFunction callback, void* data);
int icicle_remove_hook(Icicle* ptr, uint32_t id);

// Add declarations for memory hooks
// Note: Using u32 for hook IDs, although MMU might return Option<u32>
// We will handle potential None in Rust and return 0 for failure.
// We'll expose ReadAfter and Write hooks.
uint32_t icicle_add_mem_read_hook(
    Icicle* ptr, 
    MemReadHookFunction callback, 
    void* data, 
    uint64_t start_addr, 
    uint64_t end_addr);
    
uint32_t icicle_add_mem_write_hook(
    Icicle* ptr, 
    MemWriteHookFunction callback, 
    void* data, 
    uint64_t start_addr, 
    uint64_t end_addr);

// Declarations for removing hooks by type
int icicle_remove_execution_hook(Icicle* ptr, uint32_t hook_id);
int icicle_remove_mem_read_hook(Icicle* ptr, uint32_t hook_id);
int icicle_remove_mem_write_hook(Icicle* ptr, uint32_t hook_id);

// Generates a backtrace of function calls using debug information
// Returns a newly allocated C string that must be freed with icicle_free_string
// Returns NULL on failure or if no debug info is available
char* icicle_get_backtrace(Icicle* ptr, size_t max_frames);

// Generates a disassembly dump of all code in the VM
// Returns a newly allocated C string that must be freed with icicle_free_string
// Returns NULL on failure
char* icicle_dump_disasm(const Icicle* ptr);

// Returns the disassembly of the current code being executed
// Returns a newly allocated C string that must be freed with icicle_free_string
// Returns NULL on failure
char* icicle_current_disasm(const Icicle* ptr);

// Steps backward in execution by the specified number of instructions
// Returns a RunStatus value on success, UINT32_MAX (equivalent to -1 as u32) on failure
// Note: Requires a previous snapshot to be taken with icicle_vm_snapshot
uint32_t icicle_step_back(Icicle* ptr, uint64_t count);

// Goes to a specific instruction count
// Returns a RunStatus value on success, UINT32_MAX (equivalent to -1 as u32) on failure
// Note: Can only go to instruction counts that are available in snapshots
uint32_t icicle_goto_icount(Icicle* ptr, uint64_t target_icount);

// Saves a snapshot at the current execution state.
// Snapshots are required for step_back and goto_icount functionality.
// Returns 0 on success, -1 on failure.
int icicle_save_snapshot(Icicle* ptr);

// Frees a string previously returned by a string-returning function
void icicle_free_string(char* string);

// Declarations for debug instrumentation
uint32_t icicle_debug_log_write(Icicle* ptr, const char* name, uint64_t address, uint8_t size, LogWriteHookFunction callback, void* data);
uint32_t icicle_debug_log_regs(Icicle* ptr, const char* name, uint64_t address, size_t num_regs, const char** reg_names, LogRegsHookFunction callback, void* data);
int icicle_add_debug_instrumentation(Icicle* ptr);

// Coverage and instrumentation functions
uint8_t* icicle_get_coverage_map(Icicle* ptr, size_t* out_size);
int icicle_set_coverage_mode(Icicle* ptr, CoverageMode mode);
CoverageMode icicle_get_coverage_mode(Icicle* ptr);
int icicle_enable_instrumentation(Icicle* ptr, uint64_t start_addr, uint64_t end_addr);
int icicle_set_context_bits(Icicle* ptr, uint8_t bits);
uint8_t icicle_get_context_bits(Icicle* ptr);
int icicle_enable_compcov(Icicle* ptr, uint8_t level);
uint8_t icicle_get_compcov_level(Icicle* ptr);
int icicle_enable_edge_coverage(Icicle* ptr, bool enable);
bool icicle_has_edge_coverage(Icicle* ptr);
int icicle_enable_block_coverage(Icicle* ptr, bool only_blocks);
bool icicle_has_block_coverage(Icicle* ptr);
bool icicle_has_counts_coverage(Icicle* ptr);
void icicle_reset_coverage(Icicle* ptr);

// ----- NEW: Functions for listing mapped memory regions -----

/**
 * @brief Retrieves a list of physically mapped memory regions in the VM.
 *
 * @param ptr Pointer to the Icicle VM instance.
 * @param out_count Pointer to a size_t where the number of mapped regions will be stored.
 * @return A pointer to an array of MemRegionInfo structs. The caller is responsible
 *         for freeing this array using icicle_mem_list_mapped_free().
 *         Returns NULL on failure or if no regions are mapped.
 */
MemRegionInfo* icicle_mem_list_mapped(Icicle* ptr, size_t* out_count);

/**
 * @brief Frees the memory allocated for the memory region list returned by icicle_mem_list_mapped.
 *
 * @param list Pointer to the MemRegionInfo array.
 * @param count The number of elements in the list (returned by icicle_mem_list_mapped).
 */
void icicle_mem_list_mapped_free(MemRegionInfo* list, size_t count);

/**
 * @brief Serializes the current VM state (CPU and optionally memory) to a file
 *
 * @param vm_ptr Pointer to the Icicle VM instance.
 * @param filename The path where the serialized state will be saved.
 * @param include_memory Whether to include memory regions in the serialization.
 * @param log_level Controls the verbosity of logging and compression:
 *        - 0: No logging, no compression
 *        - 1: Error logging only, no compression
 *        - 2: Verbose logging, no compression
 *        - 3+: Verbose logging with compression (level = log_level - 2)
 * @return 0 on success, -1 on failure.
 * 
 * @note When log_level > 2, zstd compression is applied with compression level = log_level - 2.
 *       For example, log_level=3 enables compression level 1, log_level=5 enables level 3, etc.
 *       Maximum valid compression level is 22 (log_level=24).
 */
int icicle_serialize_vm_state(Icicle* vm_ptr, const char* filename, bool include_memory, int log_level);

/**
 * @brief Deserializes VM state from a file and applies it to the VM
 *
 * @param vm_ptr Pointer to the Icicle VM instance.
 * @param filename The path from which to load the serialized state.
 * @param apply_memory Whether to restore memory regions from the serialized state.
 * @param log_level Controls the verbosity of logging:
 *        - 0: No logging
 *        - 1: Error logging only
 *        - 2+: Verbose logging
 * @return 0 on success, -1 on failure.
 * 
 * @note This function automatically detects and handles zstd-compressed files.
 *       Compression detection is performed by checking for the zstd magic signature.
 */
int icicle_deserialize_vm_state(Icicle* vm_ptr, const char* filename, bool apply_memory, int log_level);

/**
 * @brief Serializes the current CPU state to a file (without memory)
 *
 * This is kept for backward compatibility. It calls icicle_serialize_vm_state with include_memory=false.
 *
 * @param vm_ptr Pointer to the Icicle VM instance.
 * @param filename The path where the serialized state will be saved.
 * @param log_level Controls the verbosity of logging and compression:
 *        - 0: No logging, no compression
 *        - 1: Error logging only, no compression
 *        - 2: Verbose logging, no compression
 *        - 3+: Verbose logging with compression (level = log_level - 2)
 * @return 0 on success, -1 on failure.
 * 
 * @note When log_level > 2, zstd compression is applied with compression level = log_level - 2.
 */
int icicle_serialize_cpu_state(Icicle* vm_ptr, const char* filename, int log_level);

/**
 * @brief Deserializes CPU state from a file and applies it to the VM (without memory)
 *
 * This is kept for backward compatibility. It calls icicle_deserialize_vm_state with apply_memory=false.
 *
 * @param vm_ptr Pointer to the Icicle VM instance.
 * @param filename The path from which to load the serialized state.
 * @param log_level Controls the verbosity of logging:
 *        - 0: No logging
 *        - 1: Error logging only
 *        - 2+: Verbose logging
 * @return 0 on success, -1 on failure.
 * 
 * @note This function automatically detects and handles zstd-compressed files.
 */
int icicle_deserialize_cpu_state(Icicle* vm_ptr, const char* filename, int log_level);

/**
 * @brief Returns the size in bytes that the current CPU state would require when serialized (without memory)
 *
 * @param vm_ptr Pointer to the Icicle VM instance.
 * @return The size in bytes, or 0 on error.
 */
size_t icicle_get_serialized_size(Icicle* vm_ptr);

/**
 * @brief Returns the size in bytes that the current VM state would require when serialized (with memory)
 *
 * @param vm_ptr Pointer to the Icicle VM instance.
 * @return The size in bytes, or 0 on error.
 */
size_t icicle_get_vm_serialized_size(Icicle* vm_ptr);

#ifdef __cplusplus
}
#endif

#endif // ICICLE_FFI_H
