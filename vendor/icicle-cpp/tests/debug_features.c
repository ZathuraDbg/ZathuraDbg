#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <icicle.h>
#include <string.h>
#include <limits.h>

// Utility function for hex dumping memory.
void hex_dump(const unsigned char *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % 8 == 0)
            printf("\n");
    }
    printf("\n");
}

// Callback functions for debug instrumentation testing
void my_log_write_hook(void* data, const char* name, uint64_t address, uint8_t size, uint64_t value) {
    printf("[LOG_WRITE] %s@0x%lx (%d bytes): 0x%lx\n", name, address, size, value);
}

// For the register logging
void my_log_regs_hook(void* data, const char* name, uint64_t address, size_t num_regs, const char** reg_names, const uint64_t* reg_values) {
    printf("[LOG_REGS] %s@0x%lx:\n", name, address);
    for (size_t i = 0; i < num_regs; i++) {
        printf("  %s = 0x%lx\n", reg_names[i], reg_values[i]);
    }
}

// Test the environment variable-based debug instrumentation
void test_env_debug_instrumentation() {
    printf("\n=== Testing Environment Variable Debug Instrumentation ===\n");
    
    // Set up environment variables
    setenv("ICICLE_LOG_WRITES", "var1=0x3000:4;var2=0x3004:4", 1);
    setenv("ICICLE_LOG_REGS", "point1@0x1008=rax,rbx,rcx;point2@0x1020=rsp,rbp", 1);
    setenv("BREAKPOINTS", "0x1040", 1);
    
    // Create a new x86_64 VM
    Icicle *vm = icicle_new("x86_64", 1, 1, 0, 1, 0, 1, 0, 0);
    if (!vm) {
        printf("ERROR: Failed to create VM for env debug instrumentation test\n");
        return;
    }
    
    // Map memory regions
    if (icicle_mem_map(vm, 0x1000, 0x1000, ExecuteReadWrite) != 0 ||
        icicle_mem_map(vm, 0x3000, 0x1000, ReadWrite) != 0) {
        printf("ERROR: Failed to map memory\n");
        icicle_free(vm);
        return;
    }
    
    // Set up a simple test program
    const unsigned char code[] = {
        // 0x1000: Start
        0x48, 0xC7, 0xC0, 0x00, 0x30, 0x00, 0x00,         // mov rax, 0x3000
        
        // 0x1007: Should hit first register hook (point1@0x1008)
        0x90,                                             // nop
        0x48, 0xC7, 0xC3, 0xAA, 0xAA, 0xAA, 0xAA,         // mov rbx, 0xAAAAAAAA
        0x48, 0xC7, 0xC1, 0xBB, 0xBB, 0xBB, 0xBB,         // mov rcx, 0xBBBBBBBB
        
        // 0x1016: Write to monitored address (var1@0x3000)
        0x48, 0xC7, 0x00, 0x11, 0x22, 0x33, 0x44,         // mov qword ptr [rax], 0x44332211
        
        // 0x101D: Should hit second register hook (point2@0x1020)
        0x90, 0x90, 0x90,                                 // 3 nops
        0x48, 0x89, 0xE5,                                 // mov rbp, rsp
        0x48, 0x83, 0xEC, 0x20,                           // sub rsp, 0x20
        
        // 0x102A: Write to second monitored address (var2@0x3004)
        0x48, 0xC7, 0xC0, 0x04, 0x30, 0x00, 0x00,         // mov rax, 0x3004
        0x48, 0xC7, 0x00, 0x55, 0x66, 0x77, 0x88,         // mov qword ptr [rax], 0x88776655
        
        // 0x103B: Some nops before breakpoint
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,   // 8 nops
        0x90, 0x90, 0x90, 0x90, 0x90,                     // 5 more nops
        
        // 0x1048: Should hit the breakpoint (0x1040)
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,   // 8 nops
        
        // End
        0xC3                                              // ret
    };
    
    if (icicle_mem_write(vm, 0x1000, code, sizeof(code)) != 0) {
        printf("ERROR: Failed to write code\n");
        icicle_free(vm);
        return;
    }
    
    // Set up the VM
    icicle_set_pc(vm, 0x1000);
    
    // Configure instrumentation from environment variables
    int hook_count = icicle_add_debug_instrumentation(vm);
    printf("Configured %d hooks from environment variables\n", hook_count);
    
    if (hook_count <= 0) {
        printf("ERROR: Failed to configure hooks from environment variables\n");
        icicle_free(vm);
        return;
    }
    
    // Run until we hit the breakpoint
    printf("\nRunning until breakpoint (expected at 0x1040)...\n");
    RunStatus status = icicle_run(vm);
    printf("VM stopped with status: %d\n", status);
    printf("Current PC: 0x%lx (expected: 0x1040)\n", icicle_get_pc(vm));
    
    if (status != Breakpoint || icicle_get_pc(vm) != 0x1040) {
        printf("ERROR: Breakpoint not hit or wrong breakpoint hit\n");
        icicle_free(vm);
        return;
    }
    
    // Continue to the end of execution
    printf("\nContinuing to the end of execution...\n");
    status = icicle_run(vm);
    printf("VM execution complete with status: %d\n", status);
    printf("Current PC: 0x%lx\n", icicle_get_pc(vm));
    
    // Check memory values
    size_t read_size = 0;
    unsigned char* mem_data = icicle_mem_read(vm, 0x3000, 8, &read_size);
    if (mem_data && read_size == 8) {
        printf("\nMemory values at monitored locations:\n");
        printf("var1@0x3000: ");
        for (int i = 0; i < 4; i++) {
            printf("%02X ", mem_data[i]);
        }
        printf("\n");
        
        printf("var2@0x3004: ");
        for (int i = 4; i < 8; i++) {
            printf("%02X ", mem_data[i]);
        }
        printf("\n");
        
        // Check expected values
        bool var1_ok = mem_data[0] == 0x11 && mem_data[1] == 0x22 && 
                      mem_data[2] == 0x33 && mem_data[3] == 0x44;
        bool var2_ok = mem_data[4] == 0x55 && mem_data[5] == 0x66 && 
                      mem_data[6] == 0x77 && mem_data[7] == 0x88;
        
        if (var1_ok && var2_ok) {
            printf("\nTEST PASSED: Environment variable debug instrumentation working correctly\n");
        } else {
            printf("\nTEST FAILED: Memory values don't match expected values\n");
        }
        
        icicle_free_buffer(mem_data, read_size);
    } else {
        printf("ERROR: Failed to read memory values\n");
    }
    
    // Clean up
    icicle_free(vm);
    
    // Clear environment variables for other tests
    unsetenv("ICICLE_LOG_WRITES");
    unsetenv("ICICLE_LOG_REGS");
    unsetenv("BREAKPOINTS");
}

int main() {
    test_env_debug_instrumentation();
    printf("\nTest completed.\n");
    return 0;
} 