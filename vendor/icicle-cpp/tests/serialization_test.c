#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../icicle.h"

// Test instruction bytes (simple x86_64 code)
unsigned char TEST_CODE[] = {
    0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,  // mov rax, 1
    0x48, 0xC7, 0xC7, 0x02, 0x00, 0x00, 0x00,  // mov rdi, 2
    0x48, 0x01, 0xF8,                          // add rax, rdi
    0xC3                                        // ret
};

void check_result(const char* operation, int result) {
    if (result != 0) {
        printf("ERROR: %s failed with code %d\n", operation, result);
        exit(1);
    }
}

int test_serialization() {
    printf("==== Testing CPU state serialization ====\n");
    
    printf("Creating new VM...\n");
    // Create a new VM
    Icicle* vm = icicle_new("x86_64", 0, 0, 0, 0, 0, 0, 0, 0);
    if (!vm) {
        printf("Failed to create VM\n");
        return 1;
    }
    
    printf("Mapping memory and loading code...\n");
    // Map memory for code
    check_result("Memory mapping", icicle_mem_map(vm, 0x1000, 0x1000, ExecuteReadWrite));
    
    // Write test code
    check_result("Code writing", icicle_mem_write(vm, 0x1000, TEST_CODE, sizeof(TEST_CODE)));
    
    // Setup initial state
    printf("Setting up initial CPU state...\n");
    icicle_set_pc(vm, 0x1000);
    check_result("Register write (RAX)", icicle_reg_write(vm, "rax", 0x1234567890ABCDEF));
    check_result("Register write (RBX)", icicle_reg_write(vm, "rbx", 0xFEDCBA0987654321));
    check_result("Register write (RCX)", icicle_reg_write(vm, "rcx", 0xAAAABBBBCCCCDDDD));
    
    // Execute a few instructions 
    printf("Executing instructions...\n");
    RunStatus status = icicle_step(vm, 2);
    if (status != Running) {
        printf("WARNING: Execution status is not Running: %d\n", status);
    }
    
    // Get register values before serialization
    uint64_t rax_before, rbx_before, rcx_before, pc_before;
    check_result("Register read (RAX)", icicle_reg_read(vm, "rax", &rax_before));
    check_result("Register read (RBX)", icicle_reg_read(vm, "rbx", &rbx_before));
    check_result("Register read (RCX)", icicle_reg_read(vm, "rcx", &rcx_before));
    pc_before = icicle_get_pc(vm);
    
    printf("Before serialization:\n");
    printf("  PC = 0x%lx\n", pc_before);
    printf("  RAX = 0x%lx\n", rax_before);
    printf("  RBX = 0x%lx\n", rbx_before);
    printf("  RCX = 0x%lx\n", rcx_before);
    
    size_t serialized_size = icicle_get_serialized_size(vm);
    printf("  Serialized size: %zu bytes\n", serialized_size);
    if (serialized_size == 0) {
        printf("ERROR: Failed to calculate serialized size\n");
        icicle_free(vm);
        return 1;
    }
    
    // Serialize VM state
    const char* filename = "test_state.bin";
    printf("Serializing CPU state to '%s'...\n", filename);
    int result = icicle_serialize_cpu_state(vm, filename, 0);
    if (result != 0) {
        printf("ERROR: Failed to serialize CPU state, error code: %d\n", result);
        icicle_free(vm);
        return 1;
    }
    printf("Successfully serialized CPU state to %s\n", filename);
    
    // Change some register values
    printf("Changing register values to verify restore works...\n");
    check_result("Register write (RAX)", icicle_reg_write(vm, "rax", 0));
    check_result("Register write (RBX)", icicle_reg_write(vm, "rbx", 0));
    check_result("Register write (RCX)", icicle_reg_write(vm, "rcx", 0));
    icicle_set_pc(vm, 0x1000);  // Reset PC
    
    // Verify registers changed
    uint64_t rax_changed, rbx_changed, rcx_changed, pc_changed;
    check_result("Register read (RAX)", icicle_reg_read(vm, "rax", &rax_changed));
    check_result("Register read (RBX)", icicle_reg_read(vm, "rbx", &rbx_changed));
    check_result("Register read (RCX)", icicle_reg_read(vm, "rcx", &rcx_changed));
    pc_changed = icicle_get_pc(vm);
    
    printf("After changing registers:\n");
    printf("  PC = 0x%lx\n", pc_changed);
    printf("  RAX = 0x%lx\n", rax_changed);
    printf("  RBX = 0x%lx\n", rbx_changed);
    printf("  RCX = 0x%lx\n", rcx_changed);
    
    // Deserialize VM state
    printf("Deserializing CPU state from %s...\n", filename);
    result = icicle_deserialize_cpu_state(vm, filename, 0);
    if (result != 0) {
        printf("ERROR: Failed to deserialize CPU state\n");
        icicle_free(vm);
        return 1;
    }
    printf("Successfully deserialized CPU state from %s\n", filename);
    
    // Get register values after deserialization
    uint64_t rax_after, rbx_after, rcx_after, pc_after;
    check_result("Register read (RAX)", icicle_reg_read(vm, "rax", &rax_after));
    check_result("Register read (RBX)", icicle_reg_read(vm, "rbx", &rbx_after));
    check_result("Register read (RCX)", icicle_reg_read(vm, "rcx", &rcx_after));
    pc_after = icicle_get_pc(vm);
    
    printf("After deserialization:\n");
    printf("  PC = 0x%lx\n", pc_after);
    printf("  RAX = 0x%lx\n", rax_after);
    printf("  RBX = 0x%lx\n", rbx_after);
    printf("  RCX = 0x%lx\n", rcx_after);
    
    // Verify everything matches
    int success = 1;
    if (pc_before != pc_after) {
        printf("ERROR: PC mismatch: 0x%lx vs 0x%lx\n", pc_before, pc_after);
        success = 0;
    }
    if (rax_before != rax_after) {
        printf("ERROR: RAX mismatch: 0x%lx vs 0x%lx\n", rax_before, rax_after);
        success = 0;
    }
    if (rbx_before != rbx_after) {
        printf("ERROR: RBX mismatch: 0x%lx vs 0x%lx\n", rbx_before, rbx_after);
        success = 0;
    }
    if (rcx_before != rcx_after) {
        printf("ERROR: RCX mismatch: 0x%lx vs 0x%lx\n", rcx_before, rcx_after);
        success = 0;
    }
    
    // Additional test - check that further execution works
    printf("Testing continued execution after deserialization...\n");
    RunStatus continue_status = icicle_step(vm, 2);
    if (continue_status != Running && continue_status != Halt) {
        printf("WARNING: Execution after deserialization not running: %d\n", continue_status);
    }
    
    // Check that RAX has changed after executing more instructions
    uint64_t rax_final;
    check_result("Register read (RAX)", icicle_reg_read(vm, "rax", &rax_final));
    printf("  RAX after more execution: 0x%lx\n", rax_final);
    
    if (rax_final == rax_after && continue_status == Running) {
        printf("WARNING: RAX value didn't change after execution\n");
    }
    
    icicle_free(vm);
    
    if (success) {
        printf("Serialization test PASSED!\n");
        return 0;
    } else {
        printf("Serialization test FAILED!\n");
        return 1;
    }
}

// Test error handling by trying to serialize/deserialize with invalid arguments
int test_error_handling() {
    printf("==== Testing error handling ====\n");
    
    // Create a VM for testing
    Icicle* vm = icicle_new("x86_64", 0, 0, 0, 0, 0, 0, 0, 0);
    if (!vm) {
        printf("Failed to create VM\n");
        return 1;
    }
    
    int result;
    
    // Test null VM pointer
    printf("Testing null VM pointer...\n");
    result = icicle_serialize_cpu_state(NULL, "test.bin", 0);
    if (result != -1) {
        printf("ERROR: Expected error with NULL VM pointer\n");
        icicle_free(vm);
        return 1;
    }
    
    // Test null filename
    printf("Testing null filename...\n");
    result = icicle_serialize_cpu_state(vm, NULL, 0);
    if (result != -1) {
        printf("ERROR: Expected error with NULL filename\n");
        icicle_free(vm);
        return 1;
    }
    
    // Test loading from non-existent file
    printf("Testing deserialize from non-existent file...\n");
    result = icicle_deserialize_cpu_state(vm, "nonexistent_file.bin", 0);
    if (result != -1) {
        printf("ERROR: Expected error when deserializing from non-existent file\n");
        icicle_free(vm);
        return 1;
    }
    
    // Test writing to invalid path
    printf("Testing serialize to invalid path...\n");
    result = icicle_serialize_cpu_state(vm, "/invalid/path/file.bin", 0);
    if (result != -1) {
        printf("ERROR: Expected error when serializing to invalid path\n");
        icicle_free(vm);
        return 1;
    }
    
    icicle_free(vm);
    printf("Error handling test PASSED!\n");
    return 0;
}

int main() {
    int result = test_serialization();
    if (result == 0) {
        result = test_error_handling();
    }
    printf("Tests completed with status: %d\n", result);
    return result;
} 