#include "BreakpointManager.hpp"
#include "../../../vendor/log/clue.hpp"

// Global singleton instance
static BreakpointManager g_breakpointManager;

BreakpointManager& getBreakpointManager() {
    return g_breakpointManager;
}

uint64_t BreakpointManager::lineToAddress(uint64_t lineNo) const {
    if (lineToAddressFunc_) {
        return lineToAddressFunc_(lineNo);
    }
    return 0;
}

uint64_t BreakpointManager::addressToLine(uint64_t address) const {
    if (addressToLineFunc_) {
        return addressToLineFunc_(address);
    }
    return 0;
}

bool BreakpointManager::addBreakpointToVM(uint64_t address) {
    if (icicle_ == nullptr || address == 0) {
        return false;
    }
    return icicle_add_breakpoint(icicle_, address);
}

bool BreakpointManager::removeBreakpointFromVM(uint64_t address) {
    if (icicle_ == nullptr || address == 0) {
        return false;
    }
    return icicle_remove_breakpoint(icicle_, address);
}

bool BreakpointManager::addUserBreakpoint(uint64_t lineNo) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check if breakpoint already exists
    auto it = std::ranges::find(breakpointLines_, lineNo);
    if (it != breakpointLines_.end()) {
        LOG_DEBUG("User breakpoint already exists at line " << lineNo);
        return false;
    }

    // Add to VM if available
    uint64_t address = lineToAddress(lineNo);
    if (icicle_ != nullptr && address != 0) {
        if (!addBreakpointToVM(address)) {
            LOG_WARNING("Failed to add breakpoint to VM at address 0x" << std::hex << address);
            // Continue anyway - VM might not be initialized yet
        }
    }

    // Track the breakpoint
    breakpointLines_.push_back(lineNo);

    // Update UI
    if (highlightCallback_) {
        // Highlight uses 0-based line numbers
        highlightCallback_(lineNo - 1);
    }

    LOG_DEBUG("Added user breakpoint at line " << lineNo);
    return true;
}

bool BreakpointManager::removeUserBreakpoint(uint64_t lineNo) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check if this is a silent breakpoint
    if (isSilentBreakpoint(lineNo)) {
        LOG_ALERT("Attempt to remove a silent breakpoint as user breakpoint. Ignoring.");
        return true;
    }

    // Find the breakpoint
    auto it = std::ranges::find(breakpointLines_, lineNo);
    if (it == breakpointLines_.end()) {
        LOG_DEBUG("No user breakpoint exists at line " << lineNo);
        return false;
    }

    // Remove from VM if available
    uint64_t address = lineToAddress(lineNo);
    if (icicle_ != nullptr && address != 0) {
        removeBreakpointFromVM(address);
    }

    // Remove from tracking
    breakpointLines_.erase(it);

    // Update UI
    if (removeHighlightCallback_) {
        removeHighlightCallback_(lineNo);
    }

    LOG_DEBUG("Removed user breakpoint at line " << lineNo);
    return true;
}

bool BreakpointManager::toggleBreakpoint(uint64_t lineNo) {
    // lineNo from editor is 0-based, convert to 1-based for internal use
    uint64_t internalLineNo = lineNo + 1;

    // Check if breakpoint exists (without lock, hasUserBreakpoint will acquire it)
    if (hasUserBreakpoint(internalLineNo)) {
        removeUserBreakpoint(internalLineNo);
        return false;  // Removed
    } else {
        // For addUserBreakpoint, we pass the 0-based line and it handles the conversion
        std::lock_guard<std::mutex> lock(mutex_);

        // Check if breakpoint already exists
        auto it = std::ranges::find(breakpointLines_, internalLineNo);
        if (it != breakpointLines_.end()) {
            LOG_DEBUG("User breakpoint already exists at line " << internalLineNo);
            return false;
        }

        // Add to VM if available
        uint64_t address = lineToAddress(internalLineNo);
        if (icicle_ != nullptr && address != 0) {
            if (!addBreakpointToVM(address)) {
                LOG_WARNING("Failed to add breakpoint to VM at address 0x" << std::hex << address);
            }
        }

        // Track the breakpoint
        breakpointLines_.push_back(internalLineNo);

        // Update UI (using 0-based line number)
        if (highlightCallback_) {
            highlightCallback_(lineNo);
        }

        LOG_DEBUG("Added user breakpoint at line " << internalLineNo);
        return true;  // Added
    }
}

bool BreakpointManager::hasUserBreakpoint(uint64_t lineNo) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::ranges::find(breakpointLines_, lineNo) != breakpointLines_.end();
}

std::vector<uint64_t> BreakpointManager::getUserBreakpoints() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return breakpointLines_;
}

void BreakpointManager::clearAllUserBreakpoints() {
    std::lock_guard<std::mutex> lock(mutex_);

    // Remove from VM
    if (icicle_ != nullptr) {
        for (uint64_t lineNo : breakpointLines_) {
            uint64_t address = lineToAddress(lineNo);
            if (address != 0) {
                removeBreakpointFromVM(address);
            }
        }
    }

    // Clear tracking (but we might want to keep the lines for later)
    breakpointLines_.clear();
}

bool BreakpointManager::addSilentBreakpoint(uint64_t lineNo) {
    // Silent breakpoints are not tracked in breakpointLines_
    uint64_t address = lineToAddress(lineNo);
    if (address == 0) {
        return false;
    }
    return addBreakpointToVM(address);
}

bool BreakpointManager::removeSilentBreakpoint(uint64_t lineNo) {
    uint64_t address = lineToAddress(lineNo);
    if (address == 0) {
        return false;
    }
    return removeBreakpointFromVM(address);
}

bool BreakpointManager::isSilentBreakpoint(uint64_t lineNo) const {
    if (icicle_ == nullptr) {
        return false;
    }

    size_t outSize = 0;
    uint64_t* breakpointList = icicle_breakpoint_list(icicle_, &outSize);
    if (breakpointList == nullptr) {
        return false;
    }

    uint64_t targetAddress = lineToAddress(lineNo);
    bool foundInVM = false;

    for (size_t i = 0; i < outSize; i++) {
        if (breakpointList[i] == targetAddress) {
            foundInVM = true;
            break;
        }
    }

    icicle_breakpoint_list_free(breakpointList, outSize);

    if (!foundInVM) {
        return false;
    }

    // It's a silent breakpoint if it exists in VM but not in user breakpoints
    return std::ranges::find(breakpointLines_, lineNo) == breakpointLines_.end();
}

void BreakpointManager::reapplyBreakpointsToVM() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (icicle_ == nullptr) {
        LOG_WARNING("Cannot reapply breakpoints: VM not initialized");
        return;
    }

    for (uint64_t lineNo : breakpointLines_) {
        uint64_t address = lineToAddress(lineNo);
        if (address != 0) {
            addBreakpointToVM(address);
        }
    }

    LOG_DEBUG("Reapplied " << breakpointLines_.size() << " breakpoints to VM");
}

void BreakpointManager::reset() {
    std::lock_guard<std::mutex> lock(mutex_);

    // Reset execution state
    stoppedAtBreakpoint_ = false;
    nextLineHasBreakpoint_ = false;
    tempBPLineNum_ = -1;
    stepOverBPLineNo_ = -1;
    eraseTempBP_ = false;

    // Note: We keep breakpointLines_ intact so breakpoints persist across resets
    // The caller should call reapplyBreakpointsToVM() after VM is reinitialized
}

void BreakpointManager::fullReset() {
    std::lock_guard<std::mutex> lock(mutex_);

    // Clear everything
    breakpointLines_.clear();
    stoppedAtBreakpoint_ = false;
    nextLineHasBreakpoint_ = false;
    tempBPLineNum_ = -1;
    stepOverBPLineNo_ = -1;
    eraseTempBP_ = false;
    icicle_ = nullptr;
}
