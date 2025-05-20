#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>
#include <icicle.h> 
#include <cstring>

Icicle* icicle = nullptr;

void printMemoryMappings(){
    size_t regionSize{};
    MemRegionInfo* regionInfo = icicle_mem_list_mapped(icicle, &regionSize);
    printf("Region size: %zu\n", regionSize);
    for (size_t i = 0; i < regionSize; i++) {
        printf("Region %zu: %p - %p\n", i, regionInfo[i].address, regionInfo[i].address + regionInfo[i].size);
    }
    icicle_mem_list_mapped_free(regionInfo, regionSize);
}

int main(int argc, char** argv) {
    // check if GHIDRA_SRC is set
    if (getenv("GHIDRA_SRC") == nullptr) {
        printf("ERROR: GHIDRA_SRC is not set\n");
        return 1;
    }

    if (argc < 2) {
        printf("ERROR: No argument provided\n");
        printf("Usage: %s <break|fix>\n", argv[0]);
        printf("break: break the mapping\n");
        printf("fix: fix the mapping\n");
        return 1;
    }

    icicle = icicle_new("x86_64", true, true, false, false, false, false, false, false);
    if (!icicle) {
        printf("ERROR: Failed to create x86_64 VM\n");
        return 1;
    }
    VmSnapshot* snapshot = icicle_vm_snapshot(icicle);   
   auto s = icicle_mem_map(icicle, 0x10000, 0x5000, MemoryProtection::ExecuteReadWrite);
    if (s != 0) {
        printf("Error mapping memory: %d\n", s);
    }
  
    printf("Before unmap\n");
    printMemoryMappings();
    icicle_mem_unmap(icicle, 0x10000, 0x5000);
    
    printf("After unmap\n");
    printMemoryMappings();
    icicle_mem_map(icicle, 0x10000, 0x6000, MemoryProtection::ExecuteReadWrite);
    icicle_mem_map(icicle, 0x100000, 0x60000, MemoryProtection::ExecuteReadWrite);
    
    printf("After remap\n");
    printMemoryMappings();
    
    if (strcmp(argv[1], "break") == 0) {
        size_t outSize{};
        uint8_t* out = (uint8_t*)icicle_mem_read(icicle, 0x10000, 0x5000, &outSize);
        printf("Mapping's size should be wrong\n");
    } 
    else if (strcmp(argv[1], "fix") == 0) {
        size_t outSize{};
        uint8_t* out = (uint8_t*)icicle_mem_read(icicle, 0x10000, 0x6000, &outSize);
        printf("Everything should be good now\n");
    
    }

    const char inp[300]{};
    scanf("%s", inp);

    printMemoryMappings();
    icicle_free(icicle);
    printf("Done\n");
    return 0;
}
