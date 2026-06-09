#ifndef ZATHURA_ACTIONS_HPP
#define ZATHURA_ACTIONS_HPP
#include "../app.hpp"
#include <optional>
extern std::mutex debugActionsMutex;
extern std::optional<uint64_t> remoteDisassemblyBaseAddress;
extern uint64_t remoteResumeGeneration;
extern void runActions();
extern void startDebugging();
extern void startOrRefreshRemoteDebugSession();
extern void debugContinueAction(bool skipBP);
extern bool debugAddBreakpoint(int lineNum);
extern bool debugAddBreakpointAddress(uint64_t address);
extern bool debugRemoveBreakpoint(int lineNum);
extern bool debugRemoveBreakpointAddress(uint64_t address);

// Add declarations for the UI update functions
void safeHighlightLine(int lineNo);
void processUIUpdates();
void executeInBackground(const std::function<void()>& func);
void requestRemoteUiSync(bool refreshTarget = false, bool resetCodeMemoryBase = false);

#endif //ZATHURA_ACTIONS_HPP
