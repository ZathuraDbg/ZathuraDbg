#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
// Include the Icicle API header - adjust path as needed
#include "icicle.h"

// Counter for tracking hook invocations
static int execution_hook_count = 0;
static int syscall_hook_count = 0;
static int violation_hook_count = 0;
static int mem_read_hook_count = 0;
static int mem_write_hook_count = 0;

// Detailed violation hook callback: prints details and allows execution to continue
int violation_hook_callback(void* user_data, uint64_t address, uint8_t permission, int unmapped) {
    violation_hook_count++; // Increment counter first
    const char* perm_str = "unknown";
    // Check for specific permission value passed from Rust
    // Assumes Rust passes perm::READ (1), perm::WRITE (2), or perm::EXEC (4)
    if (permission == 1) perm_str = "read";      // Check equality
    else if (permission == 2) perm_str = "write"; // Check equality
    else if (permission == 4) perm_str = "execute"; // Check equality
    // Note: Rust code currently only passes one specific violated permission bit.

    // Keep this essential log
    printf("[VIOLATION HOOK] #%d: address=0x%lx, permission=%s, unmapped=%s\n",
           violation_hook_count, address, perm_str,
           unmapped ? "true" : "false");

    // Return 1 to resume execution. Crucially, the Rust handler only advances
    // PC for the write-to-0 case. Other violations will repeat if not handled
    // differently (e.g., by stopping execution here or advancing PC in Rust).
    return 1; 
}

// Syscall hook callback - updated signature and prints args
int syscall_hook_callback(void* user_data, uint64_t syscall_nr, const SyscallArgs* args) {
    syscall_hook_count++;
    printf("[SYSCALL HOOK] #%d: Intercepted NR=%llu, Args=[RDI=0x%llx, RSI=0x%llx, RDX=0x%llx, R10=0x%llx, R8=0x%llx, R9=0x%llx]\n",
           syscall_hook_count, (unsigned long long)syscall_nr,
           (unsigned long long)args->arg0,
           (unsigned long long)args->arg1,
           (unsigned long long)args->arg2,
           (unsigned long long)args->arg3,
           (unsigned long long)args->arg4,
           (unsigned long long)args->arg5);

    // Decide return value based on syscall number
    if (syscall_nr == 1) { // sys_write
        printf("  -> Hook identified sys_write (fd=%llu). Allowing emulation to proceed.\n", (unsigned long long)args->arg0);
        return 0; // Tell Rust to continue after syscall
    } else if (syscall_nr == 60) { // sys_exit
        printf("  -> Hook identified sys_exit. Allowing emulator to halt.\n");
        return 0; // Let Rust handle the halt
    } else {
        printf("  -> Hook allowing unknown syscall %llu to proceed.\n", (unsigned long long)syscall_nr);
        return 0; // Default action: allow and continue
    }
}

// Execution hook callback: prints execution activity
void execution_hook_callback(void* user_data, uint64_t address) {
    execution_hook_count++; // Increment counter first
    // Keep this essential log, but maybe less frequently?
    // Let's keep it for now to see block execution.
    printf("[EXECUTION HOOK] #%d: address=0x%lx\n",
           execution_hook_count, address);
}

// --- Memory Hook Callbacks ---

void mem_read_callback(void* data, uint64_t address, uint8_t size, const uint8_t* value_read) {
    mem_read_hook_count++;
    printf("[MEM READ HOOK] #%d: addr=0x%llx, size=%u, data=[",
           mem_read_hook_count, (unsigned long long)address, size);
    // Print bytes read (up to 8 for brevity)
    for (uint8_t i = 0; i < size && i < 8; ++i) {
        printf("%02x ", value_read[i]);
    }
    if (size > 8) printf("... ");
    printf("]\n");
}

void mem_write_callback(void* data, uint64_t address, uint8_t size, uint64_t value_written) {
    mem_write_hook_count++;
    // Note: value_written is currently reconstructed in Rust wrapper assuming size <= 8
    printf("[MEM WRITE HOOK] #%d: addr=0x%llx, size=%u, value=0x%llx\n",
           mem_write_hook_count, (unsigned long long)address, 
           size, (unsigned long long)value_written);
}

// Helper function to print register values (can be removed if not needed for final test)
void print_regs(Icicle* vm) {
    uint64_t rax=0, rbx=0, rcx=0, rdx=0, rsp=0, pc=0, rdi=0, rsi=0;
    icicle_reg_read(vm, "rax", &rax);
    icicle_reg_read(vm, "rbx", &rbx);
    icicle_reg_read(vm, "rcx", &rcx);
    icicle_reg_read(vm, "rdx", &rdx);
    icicle_reg_read(vm, "rsp", &rsp);
    icicle_reg_read(vm, "rdi", &rdi);
    icicle_reg_read(vm, "rsi", &rsi);
    pc = icicle_get_pc(vm);

    printf("Registers: PC=0x%lx, RAX=0x%lx, RBX=0x%lx, RCX=0x%lx, RDX=0x%lx, RSP=0x%lx, RDI=0x%lx, RSI=0x%lx\n",
           pc, rax, rbx, rcx, rdx, rsp, rdi, rsi);
}

// Helper function to print memory contents (can be removed if not needed)
void print_memory(Icicle* vm, uint64_t addr, size_t size) {
    size_t out_size = 0;
    unsigned char* mem = icicle_mem_read(vm, addr, size, &out_size);
    if (mem) {
        printf("Memory at 0x%lx: ", addr);
        for (size_t i = 0; i < out_size && i < 16; i++) {
            printf("%02x ", mem[i]);
        }
        if (out_size > 16) printf("...");
        printf("\n");
        icicle_free_buffer(mem, out_size);
    } else {
        // Keep this error message
        printf("Failed to read memory at 0x%lx\n", addr);
    }
}

// Dumps the full code and current PC (can be removed)
void dump_code_with_pc(Icicle* vm, uint64_t code_addr, size_t code_size) {
    // This function can likely be removed for the final clean version
}

// Helper to trace status changes (can be removed)
const char* status_to_string(int status) {
    switch (status) {
        case 0: return "Running";
        case 1: return "InstructionLimit";
        case 2: return "Breakpoint";
        case 3: return "Interrupted";
        case 4: return "Halt"; // Important one
        case 5: return "Killed";
        case 6: return "Deadlock";
        case 7: return "OutOfMemory";
        case 8: return "Unimplemented";
        case 9: return "UnhandledException";
        default: return "Unknown";
    }
}

int main() {
    printf("\n=== HOOK TESTING ===\n\n");

    Icicle* vm = icicle_new("x86_64", 1, 1, 0, 1, 0, 1, 0, 0);
    if (!vm) {
        printf("Failed to create VM\n");
        return 1;
    }

    printf("Setting up memory...\n");
    uint64_t code_addr = 0x1000;
    uint64_t data_addr = 0x4000; // Hook reads/writes here
    uint64_t stack_base = 0x8000;
    uint64_t stack_size = 0x4000;
    if (icicle_mem_map(vm, code_addr, 0x1000, ExecuteReadWrite) != 0) return 1;
    if (icicle_mem_map(vm, data_addr, 0x1000, ReadWrite) != 0) return 1;
    if (icicle_mem_map(vm, stack_base, stack_size, ReadWrite) != 0) return 1;

    printf("Writing test program and data...\n");
    const char* message = "Hello from Icicle sys_write!\n";
    size_t message_len = strlen(message);
    if (icicle_mem_write(vm, data_addr, (const unsigned char*)message, message_len) != 0) return 1;
    // Write some initial data to the hooked area for read test
    uint64_t initial_data = 0x11223344AABBCCDD;
    if (icicle_mem_write(vm, data_addr + 0x100, (const unsigned char*)&initial_data, sizeof(initial_data)) != 0) return 1;

    unsigned char code[] = {
        // Setup registers (same as before)
        0x48, 0xC7, 0xC0, 0x11, 0x11, 0x11, 0x11,  // mov rax, 0x11111111
        0x48, 0xC7, 0xC3, 0x22, 0x22, 0x22, 0x22,  // mov rbx, 0x22222222
        // Skip some setup for brevity if needed...
        
        // Memory Write Hook Test (write to data_addr)
        0x48, 0xB8,                                 // mov rax, <data_addr + 0x200>
        ((data_addr + 0x200) >> 0) & 0xFF, ((data_addr + 0x200) >> 8) & 0xFF, 
        ((data_addr + 0x200) >> 16) & 0xFF, ((data_addr + 0x200) >> 24) & 0xFF,
        ((data_addr + 0x200) >> 32) & 0xFF, ((data_addr + 0x200) >> 40) & 0xFF,
        ((data_addr + 0x200) >> 48) & 0xFF, ((data_addr + 0x200) >> 56) & 0xFF,
        0x48, 0xC7, 0x00, 0xEE, 0xDD, 0xCC, 0xBB, // mov qword ptr [rax], 0xBBCCDDEE (dword)
        
        // Memory Read Hook Test (read from data_addr + 0x100)
        0x48, 0xB8,                                 // mov rax, <data_addr + 0x100>
        ((data_addr + 0x100) >> 0) & 0xFF, ((data_addr + 0x100) >> 8) & 0xFF, 
        ((data_addr + 0x100) >> 16) & 0xFF, ((data_addr + 0x100) >> 24) & 0xFF,
        ((data_addr + 0x100) >> 32) & 0xFF, ((data_addr + 0x100) >> 40) & 0xFF,
        ((data_addr + 0x100) >> 48) & 0xFF, ((data_addr + 0x100) >> 56) & 0xFF,
        0x48, 0x8B, 0x08,                         // mov rcx, [rax]

        // Memory Violation Test (write to addr 0)
        0x48, 0xC7, 0xC7, 0x00, 0x00, 0x00, 0x00,  // mov rdi, 0
        0xC7, 0x07, 0xEF, 0xBE, 0xAD, 0xDE,       // mov [rdi], 0xdeadbeef (will violate)
        
        // Syscall Write Test (uses data_addr)
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,  // mov rax, 1 (sys_write)
        0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00,  // mov rdi, 1 (stdout)
        0x48, 0xBE, /* ... mov rsi, data_addr ... */ 
        (data_addr >> 0) & 0xFF, (data_addr >> 8) & 0xFF, 
        (data_addr >> 16) & 0xFF, (data_addr >> 24) & 0xFF,
        (data_addr >> 32) & 0xFF, (data_addr >> 40) & 0xFF,
        (data_addr >> 48) & 0xFF, (data_addr >> 56) & 0xFF,
        0x48, 0xC7, 0xC2, /* ... mov rdx, message_len ... */
        (message_len >> 0) & 0xFF, (message_len >> 8) & 0xFF, 
        (message_len >> 16) & 0xFF, (message_len >> 24) & 0xFF,
        0x0F, 0x05,                                // syscall (write)

        // Syscall Exit Test
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,  // mov rax, 60 (sys_exit)
        0x48, 0xC7, 0xC7, 0x2A, 0x00, 0x00, 0x00,  // mov rdi, 42 (exit code)
        0x0F, 0x05                                // syscall (exit)
    };
    if (icicle_mem_write(vm, code_addr, code, sizeof(code)) != 0) return 1;

    icicle_set_sp(vm, stack_base + stack_size);
    icicle_set_pc(vm, code_addr);

    printf("Registering hooks...\n");
    int user_data = 42; 
    uint32_t violation_hook_id = icicle_add_violation_hook(vm, violation_hook_callback, &user_data);
    uint32_t syscall_hook_id = icicle_add_syscall_hook(vm, syscall_hook_callback, &user_data);
    uint32_t execution_hook_id = icicle_add_execution_hook(vm, execution_hook_callback, &user_data);
    // Register memory hooks for the data area
    uint32_t mem_read_hook_id = icicle_add_mem_read_hook(vm, mem_read_callback, &user_data, data_addr, data_addr + 0x1000);
    uint32_t mem_write_hook_id = icicle_add_mem_write_hook(vm, mem_write_callback, &user_data, data_addr, data_addr + 0x1000);
    
    printf("Hooks registered (violation=%u, syscall=%u, execution=%u, mem_read=%u, mem_write=%u)\n",
           violation_hook_id, syscall_hook_id, execution_hook_id, mem_read_hook_id, mem_write_hook_id);

    printf("\nRunning emulation...\n");
    int status = icicle_run(vm);
    printf("\nEmulation finished with status: %d (%s)\n", status, status_to_string(status));

    printf("\nHook invocation statistics:\n");
    printf("- Execution hook: %d invocations\n", execution_hook_count);
    printf("- Syscall hook: %d invocations\n", syscall_hook_count);
    printf("- Violation hook: %d invocations\n", violation_hook_count);
    printf("- Memory Read hook: %d invocations\n", mem_read_hook_count);
    printf("- Memory Write hook: %d invocations\n", mem_write_hook_count);

    printf("\nTesting hook removal...\n");
    // Attempt to remove all hooks
    if (icicle_remove_hook(vm, syscall_hook_id) == 0) printf("Syscall hook (ID=%u) removed successfully.\n", syscall_hook_id); 
        else printf("Failed to remove syscall hook (ID=%u).\n", syscall_hook_id);
    if (icicle_remove_hook(vm, violation_hook_id) == 0) printf("Violation hook (ID=%u) removed successfully.\n", violation_hook_id); 
        else printf("Failed to remove violation hook (ID=%u).\n", violation_hook_id);

    // Execution hook uses underlying VM IDs and lacks FFI removal support
    // if (icicle_remove_hook(vm, execution_hook_id) == 0) printf("Execution hook (ID=%u) removed successfully. (UNEXPECTED!)\n", execution_hook_id); 
    //     else printf("Failed to remove execution hook (ID=%u). (Expected behavior)\n", execution_hook_id);
    
    // Use new execution hook removal function (Note: Underlying VM hook may persist)
    if (icicle_remove_execution_hook(vm, execution_hook_id) == 0) {
        printf("Execution hook (FFI ID=%u) removed successfully from tracking.\n", execution_hook_id);
    } else {
        printf("Failed to remove Execution hook (FFI ID=%u) from tracking.\n", execution_hook_id);
    }

    // Use new memory hook removal functions
    if (icicle_remove_mem_read_hook(vm, mem_read_hook_id) == 0) {
        printf("Memory Read hook (ID=%u) removed successfully.\n", mem_read_hook_id);
    } else {
        printf("Failed to remove Memory Read hook (ID=%u).\n", mem_read_hook_id);
    }
    if (icicle_remove_mem_write_hook(vm, mem_write_hook_id) == 0) {
        printf("Memory Write hook (ID=%u) removed successfully.\n", mem_write_hook_id);
    } else {
        printf("Failed to remove Memory Write hook (ID=%u).\n", mem_write_hook_id);
    }

    icicle_free(vm);
    printf("\n=== TEST COMPLETE ===\n");
    return 0;
}
