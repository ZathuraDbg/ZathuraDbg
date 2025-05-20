#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <unistd.h>

#include "../icicle.h"

// Test basic serialization and deserialization
void test_basic_serialization() {
    printf("=== Testing basic serialization/deserialization ===\n");
    
    // Create a VM instance for x86-64
    Icicle* vm = icicle_new("x86_64", true, true, true, true, false, true, true, false);
    if (!vm) {
        fprintf(stderr, "Failed to create VM instance\n");
        exit(1);
    }
    
    // Set some register values to verify later
    icicle_reg_write(vm, "RAX", 0x1234567890ABCDEF);
    icicle_reg_write(vm, "RBX", 0xFEDCBA0987654321);
    icicle_reg_write(vm, "RCX", 0xAAAAAAAABBBBBBBB);
    icicle_reg_write(vm, "RDX", 0xCCCCCCCCDDDDDDDD);
    
    // Set PC to a specific value
    icicle_set_pc(vm, 0x401000);
    
    // Map some memory and write to it (to verify it's separate from serialization)
    icicle_mem_map(vm, 0x400000, 0x1000, ReadWrite);
    uint8_t test_data[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    icicle_mem_write(vm, 0x400100, test_data, sizeof(test_data));
    
    // Create a temporary filename
    char filename[256];
    sprintf(filename, "cpu_state_test_%d.bin", getpid());
    
    // Get serialized size
    size_t expected_size = icicle_get_serialized_size(vm);
    printf("Expected serialized size: %zu bytes\n", expected_size);
    
    // Serialize CPU state
    printf("Serializing CPU state to '%s'...\n", filename);
    int ret = icicle_serialize_cpu_state(vm, filename, 0); // No logging
    if (ret != 0) {
        fprintf(stderr, "Failed to serialize CPU state\n");
        icicle_free(vm);
        exit(1);
    }
    
    // Read original register values
    uint64_t orig_rax, orig_rbx, orig_rcx, orig_rdx, orig_pc;
    icicle_reg_read(vm, "RAX", &orig_rax);
    icicle_reg_read(vm, "RBX", &orig_rbx);
    icicle_reg_read(vm, "RCX", &orig_rcx);
    icicle_reg_read(vm, "RDX", &orig_rdx);
    orig_pc = icicle_get_pc(vm);
    
    printf("Original register values:\n");
    printf("  RAX: 0x%016lx\n", orig_rax);
    printf("  RBX: 0x%016lx\n", orig_rbx);
    printf("  RCX: 0x%016lx\n", orig_rcx);
    printf("  RDX: 0x%016lx\n", orig_rdx);
    printf("  PC:  0x%016lx\n", orig_pc);
    
    // Change register values
    icicle_reg_write(vm, "RAX", 0x1111111111111111);
    icicle_reg_write(vm, "RBX", 0x2222222222222222);
    icicle_reg_write(vm, "RCX", 0x3333333333333333);
    icicle_reg_write(vm, "RDX", 0x4444444444444444);
    icicle_set_pc(vm, 0x123456);
    
    // Display changed values
    uint64_t changed_rax, changed_rbx, changed_rcx, changed_rdx, changed_pc;
    icicle_reg_read(vm, "RAX", &changed_rax);
    icicle_reg_read(vm, "RBX", &changed_rbx);
    icicle_reg_read(vm, "RCX", &changed_rcx);
    icicle_reg_read(vm, "RDX", &changed_rdx);
    changed_pc = icicle_get_pc(vm);
    
    printf("Changed register values:\n");
    printf("  RAX: 0x%016lx\n", changed_rax);
    printf("  RBX: 0x%016lx\n", changed_rbx);
    printf("  RCX: 0x%016lx\n", changed_rcx);
    printf("  RDX: 0x%016lx\n", changed_rdx);
    printf("  PC:  0x%016lx\n", changed_pc);
    
    // Deserialize CPU state
    printf("Deserializing CPU state from '%s'...\n", filename);
    ret = icicle_deserialize_cpu_state(vm, filename, 0); // No logging
    if (ret != 0) {
        fprintf(stderr, "Failed to deserialize CPU state\n");
        icicle_free(vm);
        unlink(filename);
        exit(1);
    }
    
    // Read restored register values
    uint64_t restored_rax, restored_rbx, restored_rcx, restored_rdx, restored_pc;
    icicle_reg_read(vm, "RAX", &restored_rax);
    icicle_reg_read(vm, "RBX", &restored_rbx);
    icicle_reg_read(vm, "RCX", &restored_rcx);
    icicle_reg_read(vm, "RDX", &restored_rdx);
    restored_pc = icicle_get_pc(vm);
    
    printf("Restored register values:\n");
    printf("  RAX: 0x%016lx\n", restored_rax);
    printf("  RBX: 0x%016lx\n", restored_rbx);
    printf("  RCX: 0x%016lx\n", restored_rcx);
    printf("  RDX: 0x%016lx\n", restored_rdx);
    printf("  PC:  0x%016lx\n", restored_pc);
    
    // Verify restored values match original values
    bool success = true;
    if (restored_rax != orig_rax) {
        fprintf(stderr, "ERROR: RAX mismatch! Expected: 0x%016lx, Got: 0x%016lx\n", 
                orig_rax, restored_rax);
        success = false;
    }
    if (restored_rbx != orig_rbx) {
        fprintf(stderr, "ERROR: RBX mismatch! Expected: 0x%016lx, Got: 0x%016lx\n", 
                orig_rbx, restored_rbx);
        success = false;
    }
    if (restored_rcx != orig_rcx) {
        fprintf(stderr, "ERROR: RCX mismatch! Expected: 0x%016lx, Got: 0x%016lx\n", 
                orig_rcx, restored_rcx);
        success = false;
    }
    if (restored_rdx != orig_rdx) {
        fprintf(stderr, "ERROR: RDX mismatch! Expected: 0x%016lx, Got: 0x%016lx\n", 
                orig_rdx, restored_rdx);
        success = false;
    }
    if (restored_pc != orig_pc) {
        fprintf(stderr, "ERROR: PC mismatch! Expected: 0x%016lx, Got: 0x%016lx\n", 
                orig_pc, restored_pc);
        success = false;
    }
    
    if (success) {
        printf("PASS: All register values were restored correctly!\n");
    } else {
        printf("FAIL: Some register values were not restored correctly.\n");
        exit(1);
    }
    
    // Verify memory is preserved (wasn't affected by serialization)
    uint8_t read_data[16] = {0};
    size_t bytes_read = 0;
    uint8_t* result = icicle_mem_read(vm, 0x400100, sizeof(read_data), &bytes_read);
    
    if (!result || bytes_read != sizeof(test_data)) {
        fprintf(stderr, "ERROR: Failed to read memory data\n");
        success = false;
    } else {
        // Check if memory content matches
        if (memcmp(result, test_data, sizeof(test_data)) != 0) {
            fprintf(stderr, "ERROR: Memory content changed after serialization/deserialization\n");
            success = false;
        } else {
            printf("PASS: Memory content preserved (not affected by serialization)\n");
        }
        icicle_free_buffer(result, bytes_read);
    }
    
    // Clean up
    icicle_free(vm);
    unlink(filename); // Remove the temporary file
    
    if (success) {
        printf("=== Basic serialization test PASSED ===\n");
    } else {
        printf("=== Basic serialization test FAILED ===\n");
        exit(1);
    }
}

// Test serialization/deserialization with shadow stack
void test_shadow_stack_serialization() {
    printf("\n=== Testing shadow stack serialization/deserialization ===\n");
    
    // Create a VM instance with shadow stack enabled
    Icicle* vm = icicle_new("x86_64", true, true, true, true, false, true, true, false);
    if (!vm) {
        fprintf(stderr, "Failed to create VM instance\n");
        exit(1);
    }
    
    // Map memory for code
    icicle_mem_map(vm, 0x400000, 0x1000, ExecuteReadWrite);
    
    // We'll create a small function at 0x400100 that we can call
    // This will populate the shadow stack
    uint8_t call_opcodes[] = {
        0xe8, 0x05, 0x00, 0x00, 0x00,  // call 0x400105 (next instruction)
        0xc3                           // ret
    };
    icicle_mem_write(vm, 0x400100, call_opcodes, sizeof(call_opcodes));
    
    // Set PC to our function
    icicle_set_pc(vm, 0x400100);
    
    // Call the function a few times to build up shadow stack entries
    for (int i = 0; i < 5; i++) {
        printf("Running VM to build shadow stack (iteration %d)...\n", i + 1);
        RunStatus status = icicle_run_until(vm, 0x400106); // Should hit the ret
        if (status != Breakpoint) {
            fprintf(stderr, "Failed to run VM until breakpoint (status=%d)\n", status);
            icicle_free(vm);
            exit(1);
        }
        
        // Reset PC to our function for next iteration
        icicle_set_pc(vm, 0x400100);
    }
    
    // Create a temporary filename
    char filename[256];
    sprintf(filename, "cpu_state_shadow_stack_%d.bin", getpid());
    
    // Serialize CPU state
    printf("Serializing CPU state with shadow stack to '%s'...\n", filename);
    int ret = icicle_serialize_cpu_state(vm, filename, 0); // No logging
    if (ret != 0) {
        fprintf(stderr, "Failed to serialize CPU state\n");
        icicle_free(vm);
        exit(1);
    }
    
    // Create a new VM instance for deserializing
    Icicle* vm2 = icicle_new("x86_64", true, true, true, true, false, true, true, false);
    if (!vm2) {
        fprintf(stderr, "Failed to create second VM instance\n");
        icicle_free(vm);
        unlink(filename);
        exit(1);
    }
    
    // We need to map the same memory in the new VM
    icicle_mem_map(vm2, 0x400000, 0x1000, ExecuteReadWrite);
    icicle_mem_write(vm2, 0x400100, call_opcodes, sizeof(call_opcodes));
    
    // Deserialize CPU state into the new VM
    printf("Deserializing CPU state with shadow stack from '%s'...\n", filename);
    ret = icicle_deserialize_cpu_state(vm2, filename, 0); // No logging
    if (ret != 0) {
        fprintf(stderr, "Failed to deserialize CPU state\n");
        icicle_free(vm);
        icicle_free(vm2);
        unlink(filename);
        exit(1);
    }
    
    // Verify PC is at the expected location
    uint64_t pc = icicle_get_pc(vm2);
    printf("Restored PC: 0x%016lx\n", pc);
    
    if (pc != 0x400100) {
        fprintf(stderr, "ERROR: PC not properly restored. Expected: 0x400100, Got: 0x%016lx\n", pc);
        icicle_free(vm);
        icicle_free(vm2);
        unlink(filename);
        exit(1);
    }
    
    printf("PASS: Shadow stack serialization test completed\n");
    
    // Clean up
    icicle_free(vm);
    icicle_free(vm2);
    unlink(filename);
    printf("=== Shadow stack serialization test PASSED ===\n");
}

// Test error handling for serialization/deserialization
void test_error_handling() {
    printf("\n=== Testing error handling for serialization/deserialization ===\n");
    
    // Create a VM instance for testing errors
    Icicle* vm = icicle_new("x86_64", true, true, true, true, false, true, true, false);
    if (!vm) {
        fprintf(stderr, "Failed to create VM instance\n");
        exit(1);
    }
    
    // Test with NULL VM pointer
    printf("Testing NULL VM pointer...\n");
    int ret = icicle_serialize_cpu_state(NULL, "test.bin", 1);
    if (ret != -1) {
        fprintf(stderr, "ERROR: Expected failure with NULL VM pointer, but got %d\n", ret);
        icicle_free(vm);
        exit(1);
    }
    
    // Test with NULL filename
    printf("Testing NULL filename...\n");
    ret = icicle_serialize_cpu_state(vm, NULL, 1);
    if (ret != -1) {
        fprintf(stderr, "ERROR: Expected failure with NULL filename, but got %d\n", ret);
        icicle_free(vm);
        exit(1);
    }
    
    // Test with invalid file path
    printf("Testing invalid file path...\n");
    ret = icicle_serialize_cpu_state(vm, "/nonexistent/directory/test.bin", 1);
    if (ret != -1) {
        fprintf(stderr, "ERROR: Expected failure with invalid file path, but got %d\n", ret);
        icicle_free(vm);
        exit(1);
    }
    
    // Test deserialization with non-existent file
    printf("Testing deserialize with non-existent file...\n");
    ret = icicle_deserialize_cpu_state(vm, "nonexistent_file.bin", 1);
    if (ret != -1) {
        fprintf(stderr, "ERROR: Expected failure with non-existent file, but got %d\n", ret);
        icicle_free(vm);
        exit(1);
    }
    
    // Create a corrupt file
    FILE* f = fopen("corrupt.bin", "wb");
    if (f) {
        fprintf(f, "This is not a valid serialized state file");
        fclose(f);
        
        // Test deserialization with corrupt file
        printf("Testing deserialize with corrupt file...\n");
        ret = icicle_deserialize_cpu_state(vm, "corrupt.bin", 1);
        if (ret != -1) {
            fprintf(stderr, "ERROR: Expected failure with corrupt file, but got %d\n", ret);
            icicle_free(vm);
            unlink("corrupt.bin");
            exit(1);
        }
        
        unlink("corrupt.bin");
    }
    
    // Clean up
    icicle_free(vm);
    printf("=== Error handling test PASSED ===\n");
}

int main() {
    printf("CPU State Serialization Tests\n");
    printf("-----------------------------\n");
    
    test_basic_serialization();
    test_shadow_stack_serialization();
    test_error_handling();
    
    printf("\nAll tests PASSED!\n");
    return 0;
} 