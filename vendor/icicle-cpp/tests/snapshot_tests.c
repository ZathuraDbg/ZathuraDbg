#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include "icicle.h"

// Test program that writes some test values to registers and memory
void write_test_values(Icicle* vm) {
    printf("Writing test values:\n");
    printf("  RAX = 0x1234567890ABCDEF\n");
    printf("  RBX = 0xFEDCBA0987654321\n");
    printf("  RCX = 0xDEADBEEFCAFEBABE\n");
    printf("  Memory[0x1000] = DE AD BE EF CA FE BA BE\n");

    // Write some test values to registers
    icicle_reg_write(vm, "rax", 0x1234567890ABCDEF);
    icicle_reg_write(vm, "rbx", 0xFEDCBA0987654321);
    icicle_reg_write(vm, "rcx", 0xDEADBEEFCAFEBABE);

    // Write some test values to memory
    uint8_t test_data[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
    icicle_mem_write(vm, 0x1000, test_data, sizeof(test_data));
}

// Verify register and memory values
int verify_values(Icicle* vm, const char* stage) {
    printf("\nVerifying values at stage: %s\n", stage);

    // Define expected values based on stage
    uint64_t expected_rax, expected_rbx, expected_rcx;
    uint8_t expected_mem[8];

    if (strcmp(stage, "Modified State") == 0) {
        expected_rax = 0x1111111111111111;
        expected_rbx = 0x2222222222222222;
        expected_rcx = 0x3333333333333333;
        uint8_t modified_mem[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
        memcpy(expected_mem, modified_mem, sizeof(expected_mem));
    } else {
        // Initial State or Restored State
        expected_rax = 0x1234567890ABCDEF;
        expected_rbx = 0xFEDCBA0987654321;
        expected_rcx = 0xDEADBEEFCAFEBABE;
        uint8_t initial_mem[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
        memcpy(expected_mem, initial_mem, sizeof(expected_mem));
    }

    // Check registers
    uint64_t rax, rbx, rcx;
    if (icicle_reg_read(vm, "rax", &rax) != 0) {
        printf("Failed to read RAX register\n");
        return 0;
    }
    if (rax != expected_rax) {
        printf("RAX mismatch: expected=0x%lx, got=0x%lx\n", expected_rax, rax);
        return 0;
    }
    printf("  RAX = 0x%lx [OK]\n", rax);

    if (icicle_reg_read(vm, "rbx", &rbx) != 0) {
        printf("Failed to read RBX register\n");
        return 0;
    }
    if (rbx != expected_rbx) {
        printf("RBX mismatch: expected=0x%lx, got=0x%lx\n", expected_rbx, rbx);
        return 0;
    }
    printf("  RBX = 0x%lx [OK]\n", rbx);

    if (icicle_reg_read(vm, "rcx", &rcx) != 0) {
        printf("Failed to read RCX register\n");
        return 0;
    }
    if (rcx != expected_rcx) {
        printf("RCX mismatch: expected=0x%lx, got=0x%lx\n", expected_rcx, rcx);
        return 0;
    }
    printf("  RCX = 0x%lx [OK]\n", rcx);
    
    // Check memory
    size_t read_size;
    uint8_t verify_data[8];
    uint8_t* read_data = icicle_mem_read(vm, 0x1000, sizeof(verify_data), &read_size);
    if (!read_data) {
        printf("Failed to read memory at 0x1000\n");
        return 0;
    }
    if (read_size != sizeof(verify_data)) {
        printf("Memory read size mismatch: expected=%zu, got=%zu\n", sizeof(verify_data), read_size);
        icicle_free_buffer(read_data, read_size);
        return 0;
    }
    memcpy(verify_data, read_data, read_size);
    icicle_free_buffer(read_data, read_size);
    
    if (memcmp(verify_data, expected_mem, sizeof(verify_data)) != 0) {
        printf("Memory content mismatch at 0x1000:\n");
        printf("  Expected: ");
        for (size_t i = 0; i < sizeof(expected_mem); i++) printf("%02X ", expected_mem[i]);
        printf("\n  Got:      ");
        for (size_t i = 0; i < sizeof(verify_data); i++) printf("%02X ", verify_data[i]);
        printf("\n");
        return 0;
    }
    printf("  Memory[0x1000] = ");
    for (size_t i = 0; i < sizeof(verify_data); i++) printf("%02X ", verify_data[i]);
    printf("[OK]\n");
    
    return 1;
}

int main() {
    printf("Initializing VM with x86_64 architecture...\n");
    // Initialize VM with x86_64 architecture
    Icicle* vm = icicle_new("x86_64", false, false, false, false, false, false, false, false);
    if (!vm) {
        printf("Failed to create VM\n");
        return 1;
    }
    printf("VM created successfully\n");

    // Map some memory for testing
    printf("\nMapping memory region: address=0x1000, size=0x1000, perm=ReadWrite\n");
    if (icicle_mem_map(vm, 0x1000, 0x1000, ReadWrite) != 0) {
        printf("Failed to map memory\n");
        icicle_free(vm);
        return 1;
    }
    printf("Memory mapped successfully\n");

    // Write initial test values
    printf("\n=== Initial State ===\n");
    write_test_values(vm);
    
    // Verify initial values
    if (!verify_values(vm, "Initial State")) {
        printf("Initial value verification failed\n");
        icicle_free(vm);
        return 1;
    }
    printf("Initial state verification completed successfully\n");

    // Take a snapshot
    printf("\n=== Taking Snapshot ===\n");
    VmSnapshot* snapshot = icicle_vm_snapshot(vm);
    if (!snapshot) {
        printf("Failed to create snapshot\n");
        icicle_free(vm);
        return 1;
    }
    printf("Snapshot created successfully\n");

    // Modify values
    printf("\n=== Modifying State ===\n");
    printf("Writing new values:\n");
    printf("  RAX = 0x1111111111111111\n");
    printf("  RBX = 0x2222222222222222\n");
    printf("  RCX = 0x3333333333333333\n");
    printf("  Memory[0x1000] = 11 22 33 44 55 66 77 88\n");

    icicle_reg_write(vm, "rax", 0x1111111111111111);
    icicle_reg_write(vm, "rbx", 0x2222222222222222);
    icicle_reg_write(vm, "rcx", 0x3333333333333333);
    
    uint8_t new_data[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    icicle_mem_write(vm, 0x1000, new_data, sizeof(new_data));

    // Verify modified values
    if (!verify_values(vm, "Modified State")) {
        printf("Modified value verification failed\n");
        icicle_vm_snapshot_free(snapshot);
        icicle_free(vm);
        return 1;
    }
    printf("Modified state verification completed successfully\n");

    // Restore from snapshot
    printf("\n=== Restoring Snapshot ===\n");
    if (icicle_vm_restore(vm, snapshot) != 0) {
        printf("Failed to restore from snapshot\n");
        icicle_vm_snapshot_free(snapshot);
        icicle_free(vm);
        return 1;
    }
    printf("Snapshot restored successfully\n");

    // Verify restored values
    if (!verify_values(vm, "Restored State")) {
        printf("Restored value verification failed\n");
        icicle_vm_snapshot_free(snapshot);
        icicle_free(vm);
        return 1;
    }
    printf("Restored state verification completed successfully\n");

    // Cleanup
    printf("\n=== Cleanup ===\n");
    printf("Freeing snapshot...\n");
    icicle_vm_snapshot_free(snapshot);
    printf("Freeing VM...\n");
    icicle_free(vm);

    printf("\nSnapshot test completed successfully!\n");
    return 0;
} 