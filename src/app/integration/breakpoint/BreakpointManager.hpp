#ifndef ZATHURA_BREAKPOINT_MANAGER_HPP
#define ZATHURA_BREAKPOINT_MANAGER_HPP

#include <cstdint>
#include <vector>
#include <mutex>
#include <algorithm>
#include <functional>
#include "icicle.h"

/**
 * BreakpointManager - Centralized breakpoint management for the debugger.
 *
 * This class encapsulates all breakpoint-related state and operations,
 * providing thread-safe access and clear separation between user-set
 * breakpoints and silent (internal) breakpoints.
 *
 * User breakpoints: Set by the user via F9 or context menu, persistent across runs
 * Silent breakpoints: Internally set for step-over, run-until-here, end-of-code detection
 */
class BreakpointManager {
public:
    // Callback types for UI integration
    using HighlightCallback = std::function<void(uint64_t lineNo)>;
    using RemoveHighlightCallback = std::function<void(uint64_t lineNo)>;
    using LineToAddressFunc = std::function<uint64_t(uint64_t lineNo)>;
    using AddressToLineFunc = std::function<uint64_t(uint64_t address)>;

    BreakpointManager() = default;
    ~BreakpointManager() = default;

    // Non-copyable, non-movable (singleton-like usage)
    BreakpointManager(const BreakpointManager&) = delete;
    BreakpointManager& operator=(const BreakpointManager&) = delete;

    /**
     * Set the Icicle VM instance for breakpoint operations.
     * Must be called before any breakpoint operations that require VM interaction.
     */
    void setIcicle(Icicle* ic) { icicle_ = ic; }

    /**
     * Get the current Icicle instance.
     */
    Icicle* getIcicle() const { return icicle_; }

    /**
     * Set callback functions for UI operations.
     */
    void setHighlightCallback(HighlightCallback cb) { highlightCallback_ = std::move(cb); }
    void setRemoveHighlightCallback(RemoveHighlightCallback cb) { removeHighlightCallback_ = std::move(cb); }
    void setLineToAddressFunc(LineToAddressFunc func) { lineToAddressFunc_ = std::move(func); }
    void setAddressToLineFunc(AddressToLineFunc func) { addressToLineFunc_ = std::move(func); }

    // ==================== User Breakpoint Operations ====================

    /**
     * Add a user breakpoint at the specified line number.
     * @param lineNo The 1-based line number in the source code
     * @return true if the breakpoint was added successfully
     */
    bool addUserBreakpoint(uint64_t lineNo);

    /**
     * Remove a user breakpoint from the specified line number.
     * @param lineNo The 1-based line number in the source code
     * @return true if the breakpoint was removed successfully
     */
    bool removeUserBreakpoint(uint64_t lineNo);

    /**
     * Toggle a breakpoint at the specified line number.
     * If a breakpoint exists, it will be removed; otherwise, it will be added.
     * @param lineNo The 0-based line number (cursor position from editor)
     * @return true if a breakpoint was added, false if removed
     */
    bool toggleBreakpoint(uint64_t lineNo);

    /**
     * Check if a user breakpoint exists at the specified line number.
     * @param lineNo The 1-based line number
     * @return true if a user breakpoint exists at this line
     */
    bool hasUserBreakpoint(uint64_t lineNo) const;

    /**
     * Get all user-set breakpoint line numbers.
     * @return A copy of the breakpoint lines vector
     */
    std::vector<uint64_t> getUserBreakpoints() const;

    /**
     * Clear all user breakpoints (but keep their line numbers for re-adding after reset).
     */
    void clearAllUserBreakpoints();

    // ==================== Silent Breakpoint Operations ====================

    /**
     * Add a silent (internal) breakpoint at the specified line number.
     * Silent breakpoints are not tracked in breakpointLines_ and are not shown in UI.
     * @param lineNo The 1-based line number
     * @return true if the breakpoint was added successfully
     */
    bool addSilentBreakpoint(uint64_t lineNo);

    /**
     * Remove a silent breakpoint from the specified line number.
     * @param lineNo The 1-based line number
     * @return true if the breakpoint was removed successfully
     */
    bool removeSilentBreakpoint(uint64_t lineNo);

    /**
     * Check if a breakpoint at the given line is a silent (internal) breakpoint.
     * A silent breakpoint exists in the VM but not in the user's breakpointLines_.
     * @param lineNo The 1-based line number
     * @return true if this is a silent breakpoint
     */
    bool isSilentBreakpoint(uint64_t lineNo) const;

    // ==================== Temporary Breakpoint State ====================

    /**
     * Set the temporary breakpoint line number (for run-until-here).
     */
    void setTempBreakpointLine(int lineNo) { tempBPLineNum_ = lineNo; }

    /**
     * Get the temporary breakpoint line number.
     */
    int getTempBreakpointLine() const { return tempBPLineNum_; }

    /**
     * Set the step-over breakpoint line number.
     */
    void setStepOverBreakpointLine(int lineNo) { stepOverBPLineNo_ = lineNo; }

    /**
     * Get the step-over breakpoint line number.
     */
    int getStepOverBreakpointLine() const { return stepOverBPLineNo_; }

    /**
     * Set whether the temporary breakpoint should be erased.
     */
    void setEraseTempBP(bool value) { eraseTempBP_ = value; }

    /**
     * Check if the temporary breakpoint should be erased.
     */
    bool shouldEraseTempBP() const { return eraseTempBP_; }

    // ==================== Execution State ====================

    /**
     * Set whether execution is stopped at a breakpoint.
     */
    void setStoppedAtBreakpoint(bool value) { stoppedAtBreakpoint_ = value; }

    /**
     * Check if execution is stopped at a breakpoint.
     */
    bool isStoppedAtBreakpoint() const { return stoppedAtBreakpoint_; }

    /**
     * Set whether the next line has a breakpoint.
     */
    void setNextLineHasBreakpoint(bool value) { nextLineHasBreakpoint_ = value; }

    /**
     * Check if the next line has a breakpoint.
     */
    bool doesNextLineHaveBreakpoint() const { return nextLineHasBreakpoint_; }

    // ==================== VM Breakpoint Operations ====================

    /**
     * Re-apply all user breakpoints to the VM.
     * Called after VM initialization or reset.
     */
    void reapplyBreakpointsToVM();

    /**
     * Reset the breakpoint manager state (but preserve user breakpoint line numbers).
     */
    void reset();

    /**
     * Full reset including clearing user breakpoint line numbers.
     */
    void fullReset();

    // ==================== Low-level Access (for backward compatibility) ====================

    /**
     * Get direct access to the breakpoint lines vector.
     * @deprecated Use getUserBreakpoints() or specific add/remove methods instead.
     */
    std::vector<uint64_t>& getBreakpointLinesRef() { return breakpointLines_; }

    /**
     * Get the mutex for external synchronization if needed.
     * @deprecated Prefer using the thread-safe methods of this class.
     */
    std::mutex& getMutex() { return mutex_; }

private:
    /**
     * Convert a line number to an address using the configured function.
     */
    uint64_t lineToAddress(uint64_t lineNo) const;

    /**
     * Convert an address to a line number using the configured function.
     */
    uint64_t addressToLine(uint64_t address) const;

    /**
     * Internal helper to add a breakpoint to the VM.
     */
    bool addBreakpointToVM(uint64_t address);

    /**
     * Internal helper to remove a breakpoint from the VM.
     */
    bool removeBreakpointFromVM(uint64_t address);

    // Core state
    Icicle* icicle_ = nullptr;
    mutable std::mutex mutex_;

    // User-set breakpoints (line numbers, 1-based)
    std::vector<uint64_t> breakpointLines_;

    // Temporary breakpoint state
    int tempBPLineNum_ = -1;
    int stepOverBPLineNo_ = -1;
    bool eraseTempBP_ = false;

    // Execution state
    bool stoppedAtBreakpoint_ = false;
    bool nextLineHasBreakpoint_ = false;

    // Callbacks for UI integration
    HighlightCallback highlightCallback_;
    RemoveHighlightCallback removeHighlightCallback_;
    LineToAddressFunc lineToAddressFunc_;
    AddressToLineFunc addressToLineFunc_;
};

// Global instance for backward compatibility during migration
extern BreakpointManager& getBreakpointManager();

#endif // ZATHURA_BREAKPOINT_MANAGER_HPP
