#include "interpreter.hpp"

VmSnapshot* saveICSnapshot(Icicle* icicle){
    if (icicle == nullptr){
        return nullptr;
    }

    return icicle_vm_snapshot(icicle);
}

Icicle* initIC()
{
    if (!isDebugReady) {
        LOG_ERROR("Debug mode is not ready");
    }

    const auto vm = icicle_new(codeInformation.archStr, false, true, false, false, false, false, false, false);
    if (!vm)
    {
        printf("Failed to initialize VM\n");
        return nullptr;
    }

    LOG_INFO("Initiation complete...");
    initArch();


    if (!breakpointLines.empty())
    {
        for (auto& line : breakpointLines)
        {
            // addBreakpointToLine(line);
            icicle_add_breakpoint(vm, lineNoToAddress(line));
        }
    }

    icicle = vm;
    return vm;
}

bool createStack(Icicle* ic)
{
    LOG_INFO("Creating stack...");
    if (ic == nullptr)
    {
        ic = initIC();
        if (!ic){
            LOG_ERROR("Icicle initilisation failed... Quitting!");
            return false;
        }
    }


    LOG_INFO("Checking mappings...");
    // Check if the stack region is already mapped
    bool alreadyMapped = false;
    size_t regionCount = 0;
    MemRegionInfo* regions = icicle_mem_list_mapped(ic, &regionCount);

    if (regions) {
        for (size_t i = 0; i < regionCount; i++) {
            // Check if this region overlaps with our stack region
            if ((regions[i].address <= STACK_ADDRESS &&
                 regions[i].address + regions[i].size > STACK_ADDRESS) ||
                (regions[i].address >= STACK_ADDRESS &&
                 regions[i].address < STACK_ADDRESS + STACK_SIZE)) {
                LOG_INFO("Stack region already mapped - skipping map operation");
                alreadyMapped = true;
                break;
            }
        }
        if (!alreadyMapped)
        {
            LOG_ERROR("stack regions are not mapped yet!");
        }

        icicle_mem_list_mapped_free(regions, regionCount);
    }

    auto* zeroBuf = static_cast<uint8_t*>(malloc(STACK_SIZE));
    memset(zeroBuf, 0, STACK_SIZE);
    LOG_INFO("Stack mapping if not done already.");
    // Only map if not already mapped
    if (!alreadyMapped) {
        const auto mapped = icicle_mem_map(ic, STACK_ADDRESS, STACK_SIZE, MemoryProtection::ReadWrite);
        if (mapped == -1)
        {
            LOG_ERROR("Icicle was unable to map memory for the stack.");
            free(zeroBuf);
            return false;
        }
        for (uint64_t off = 0; off < STACK_SIZE; off += 0x1000) {
            size_t out = 0;
            // A 1‑byte read is enough to trigger the lazy page allocation
            const auto s = icicle_mem_read(icicle, STACK_ADDRESS + off, 1, &out);
            icicle_free_buffer(s, 1);
        }
    }
    LOG_INFO("Attempting a mem_write");
    const auto mapped = icicle_mem_write(ic, STACK_ADDRESS, zeroBuf, STACK_SIZE);
    if (mapped == -1)
    {
        LOG_WARNING("Icicle was unable to zero memory for the stack.");
        LOG_WARNING("Something may be wrong, proceeding anyways...");
    }
    free(zeroBuf);

    const uint64_t stackBase = STACK_ADDRESS + STACK_SIZE;
    icicle_reg_write(ic, archSPStr, stackBase);
    icicle_reg_write(ic, archBPStr, stackBase);

    stackArraysZeroed = false;
    LOG_INFO("Stack created successfully!");
    return true;
}

bool resetState(bool reInit){
    LOG_INFO("Resetting state...");
    criticalSection.lock();

    {
        std::lock_guard<std::mutex> lk(debugReadyMutex);
        isDebugReady = false;
    }

    codeHasRun = false;
    stepClickedOnce = false;
    continueOverBreakpoint = false;
    debugPaused = false;
    skipBreakpoints = false;
    executionComplete = false;
    wasStepOver = false;
    wasJumpAndStepOver = false;
    stackArraysZeroed = false;
    stoppedAtBreakpoint = false;
    isEndBreakpointSet = false;

    codeCurrentLen = 0;
    codeFinalLen = 0;
    lineNo = 0;
    expectedIP = 0;

    assembly.clear();
    assembly.str("");
    instructionSizes.clear();

    editor->ClearExtraCursors();
    editor->ClearSelections();
    editor->HighlightDebugCurrentLine(-1);

    if (icicle != nullptr)
    {
        icicle_free(icicle);
        icicle = nullptr;
    }

    if (ks != nullptr)
    {
        ks_close(ks);
        ks = nullptr;
    }


    if (!vmSnapshots.empty())
    {
        for (int j = 0; j < vmSnapshots.size(); j++)
        {
            icicle_vm_snapshot_free(vmSnapshots.top());
            vmSnapshots.pop();
        }
        vmSnapshots = {};
    }

    labels.clear();
    emptyLineNumbers.clear();
    addressLineNoMap.clear();
    labelLineNoMapInternal.clear();


    labels = {};
    emptyLineNumbers = {};


    labelLineNoMapInternal = {};

    if (reInit)
    {
        if (getBytes(selectedFile).empty()) {
            criticalSection.unlock();
            return false;
        }
    }

    for (const auto &key: registerValueMap | std::views::keys){
        registerValueMap[key] = "0x00";
    }

    stackArraysZeroed = false;

    codeBuf.clear();

    LOG_DEBUG("State reset completed!");
    criticalSection.unlock();
    return true;
}
