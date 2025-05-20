#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>  // For timing

#include "../icicle.h"

// Helper function to get file size
off_t get_file_size(const char* filename) {
    struct stat st;
    if (stat(filename, &st) == 0) {
        return st.st_size;
    }
    return -1;
}

// Test compression levels for serialization
void test_compression_levels() {
    printf("\n==== Testing Serialization Compression Levels ====\n");
    
    // Create a VM instance for x86-64
    Icicle* vm = icicle_new("x86_64", true, true, true, true, false, true, true, false);
    if (!vm) {
        fprintf(stderr, "Failed to create VM instance\n");
        exit(1);
    }
    
    // Map a large memory region to demonstrate compression benefits
    const uint64_t mem_addr = 0x400000;
    const uint64_t mem_size = 10 * 1024 * 1024; // 10 MB
    
    printf("Mapping a %lu MB memory region at 0x%lx\n", mem_size / (1024 * 1024), mem_addr);
    if (icicle_mem_map(vm, mem_addr, mem_size, ReadWrite) != 0) {
        fprintf(stderr, "Failed to map memory\n");
        icicle_free(vm);
        exit(1);
    }
    
    // Fill memory with a pattern that compresses well (repeating data)
    uint8_t* pattern = malloc(1024); // 1KB pattern
    if (!pattern) {
        fprintf(stderr, "Failed to allocate pattern buffer\n");
        icicle_free(vm);
        exit(1);
    }
    
    // Create a pattern with good compression characteristics
    for (int i = 0; i < 1024; i++) {
        pattern[i] = (i % 256);
    }
    
    // Write the pattern repeatedly to memory
    for (uint64_t offset = 0; offset < mem_size; offset += 1024) {
        if (icicle_mem_write(vm, mem_addr + offset, pattern, 1024) != 0) {
            fprintf(stderr, "Failed to write to memory at 0x%lx\n", mem_addr + offset);
            free(pattern);
            icicle_free(vm);
            exit(1);
        }
    }
    
    free(pattern); // Free the pattern buffer
    
    // Set some register values
    icicle_reg_write(vm, "RAX", 0x1234567890ABCDEF);
    icicle_reg_write(vm, "RBX", 0xFEDCBA0987654321);
    icicle_reg_write(vm, "RCX", 0xAAAAAAAABBBBBBBB);
    icicle_reg_write(vm, "RDX", 0xCCCCCCCCDDDDDDDD);
    
    // Set PC to a specific value
    icicle_set_pc(vm, 0x401000);
    
    // Print expected uncompressed size
    size_t expected_size = icicle_get_vm_serialized_size(vm);
    printf("Expected serialized size without compression: %zu bytes (%.2f MB)\n", 
           expected_size, expected_size / (1024.0 * 1024.0));
    
    // For keeping track of performance results
    typedef struct {
        int level;
        char filename[256];
        off_t size;
        double compression_ratio;
        double serialize_time;
        double deserialize_time;
    } CompressionResult;
    
    CompressionResult results[6]; // 5 compression levels + uncompressed
    int result_count = 0;
    
    // Test different compression levels
    char filename[256];
    
    // First test uncompressed for baseline
    sprintf(filename, "vm_state_uncompressed.bin");
    printf("\nSerializing VM state WITHOUT compression to '%s'...\n", filename);
    
    clock_t start_time = clock();
    int ret = icicle_serialize_vm_state(vm, filename, true, 0); // log_level 0 = no compression
    clock_t end_time = clock();
    double time_taken = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
    
    if (ret == 0) {
        off_t uncompressed_size = get_file_size(filename);
        printf("Uncompressed size: %ld bytes (%.2f MB)\n", 
               uncompressed_size, uncompressed_size / (1024.0 * 1024.0));
        printf("Serialization time: %.3f seconds\n", time_taken);
        
        // Record the results
        results[result_count].level = 0;
        strcpy(results[result_count].filename, filename);
        results[result_count].size = uncompressed_size;
        results[result_count].compression_ratio = 1.0;
        results[result_count].serialize_time = time_taken;
        results[result_count].deserialize_time = 0.0; // Will measure below
        
        // Now time deserialization for uncompressed
        Icicle* vm2 = icicle_new("x86_64", true, true, true, true, false, true, true, false);
        if (vm2) {
            printf("Deserializing VM state from '%s'...\n", filename);
            start_time = clock();
            ret = icicle_deserialize_vm_state(vm2, filename, true, 0);
            end_time = clock();
            time_taken = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
            printf("Deserialization time: %.3f seconds\n", time_taken);
            results[result_count].deserialize_time = time_taken;
            icicle_free(vm2);
        }
        
        result_count++;
    }
    
    // Now test different compression levels
    for (int level = 1; level <= 5; level++) {
        int log_level = level + 2; // Convert to log_level (3 = level 1, 4 = level 2, etc.)
        
        sprintf(filename, "vm_state_compressed_level%d.bin", level);
        
        printf("\nSerializing VM state with compression level %d to '%s'...\n", level, filename);
        
        // Time the serialization
        start_time = clock();
        ret = icicle_serialize_vm_state(vm, filename, true, log_level);
        end_time = clock();
        time_taken = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
        
        if (ret != 0) {
            fprintf(stderr, "Failed to serialize VM state with compression level %d\n", level);
            continue;
        }
        
        // Get compressed file size
        off_t compressed_size = get_file_size(filename);
        double ratio = 0.0;
        if (expected_size > 0 && compressed_size > 0) {
            ratio = (double)expected_size / compressed_size;
        }
        
        printf("Compressed size: %ld bytes (%.2f MB)\n", 
               compressed_size, compressed_size / (1024.0 * 1024.0));
        printf("Compression ratio: %.2fx\n", ratio);
        printf("Serialization time: %.3f seconds\n", time_taken);
        
        // Record the results
        results[result_count].level = level;
        strcpy(results[result_count].filename, filename);
        results[result_count].size = compressed_size;
        results[result_count].compression_ratio = ratio;
        results[result_count].serialize_time = time_taken;
        results[result_count].deserialize_time = 0.0; // Will measure below
        
        // Now test and time deserialization
        Icicle* vm2 = icicle_new("x86_64", true, true, true, true, false, true, true, false);
        if (!vm2) {
            fprintf(stderr, "Failed to create second VM instance\n");
            continue;
        }
        
        printf("Deserializing VM state from '%s'...\n", filename);
        
        // Time the deserialization
        start_time = clock();
        ret = icicle_deserialize_vm_state(vm2, filename, true, 0);
        end_time = clock();
        time_taken = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
        
        printf("Deserialization time: %.3f seconds\n", time_taken);
        results[result_count].deserialize_time = time_taken;
        
        if (ret != 0) {
            fprintf(stderr, "Failed to deserialize VM state\n");
            icicle_free(vm2);
            continue;
        }
        
        // Verify register values
        uint64_t rax, rbx, rcx, rdx, pc;
        icicle_reg_read(vm2, "RAX", &rax);
        icicle_reg_read(vm2, "RBX", &rbx);
        icicle_reg_read(vm2, "RCX", &rcx);
        icicle_reg_read(vm2, "RDX", &rdx);
        pc = icicle_get_pc(vm2);
        
        printf("Deserialized state verification:\n");
        printf("  PC = 0x%lx %s\n", pc, pc == 0x401000 ? "✓" : "✗");
        printf("  RAX = 0x%lx %s\n", rax, rax == 0x1234567890ABCDEF ? "✓" : "✗");
        printf("  RBX = 0x%lx %s\n", rbx, rbx == 0xFEDCBA0987654321 ? "✓" : "✗");
        printf("  RCX = 0x%lx %s\n", rcx, rcx == 0xAAAAAAAABBBBBBBB ? "✓" : "✗");
        printf("  RDX = 0x%lx %s\n", rdx, rdx == 0xCCCCCCCCDDDDDDDD ? "✓" : "✗");
        
        // Verify memory content
        size_t mem_read_size = 0;
        uint8_t* mem_content = icicle_mem_read(vm2, mem_addr, 1024, &mem_read_size);
        if (mem_content && mem_read_size == 1024) {
            bool memory_correct = true;
            for (int i = 0; i < 1024 && memory_correct; i++) {
                if (mem_content[i] != (i % 256)) {
                    memory_correct = false;
                }
            }
            printf("  Memory content verification: %s\n", memory_correct ? "✓" : "✗");
        } else {
            printf("  Memory content verification: Failed to read memory\n");
        }
        
        if (mem_content) {
            icicle_free_buffer(mem_content, mem_read_size);
        }
        
        // Clean up VM but keep the files for now
        icicle_free(vm2);
        result_count++;
    }
    
    // Print summary of all results
    printf("\n==== Compression Performance Summary ====\n");
    printf("%-5s %-35s %-15s %-15s %-20s %-20s\n", 
           "Level", "Filename", "Size (bytes)", "Ratio", "Serialize Time (s)", "Deserialize Time (s)");
    printf("--------------------------------------------------------------------------------------------------------------\n");
    
    for (int i = 0; i < result_count; i++) {
        printf("%-5d %-35s %-15ld %-15.2f %-20.3f %-20.3f\n", 
               results[i].level, 
               results[i].filename, 
               results[i].size, 
               results[i].compression_ratio,
               results[i].serialize_time,
               results[i].deserialize_time);
    }
    
    icicle_free(vm);
    printf("\n==== Compression test completed ====\n");
    
    // Clean up all files after displaying results
    printf("Cleaning up temporary files...\n");
    for (int i = 0; i < result_count; i++) {
        printf("Removing %s\n", results[i].filename);
        unlink(results[i].filename);
    }
}

int main() {
    test_compression_levels();
    return 0;
} 