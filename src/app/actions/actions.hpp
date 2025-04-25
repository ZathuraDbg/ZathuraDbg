#ifndef ZATHURA_ACTIONS_HPP
#define ZATHURA_ACTIONS_HPP
#include "../app.hpp"
extern std::mutex debugActionsMutex;
extern void runActions();
extern void startDebugging();
extern void debugContinueAction(bool skipBP);
extern bool debugAddBreakpoint(int lineNum);
extern bool debugRemoveBreakpoint(int lineNum);

// Add declarations for the UI update functions
void safeHighlightLine(int lineNo);
void processUIUpdates();
void executeInBackground(std::function<void()> func);

#endif //ZATHURA_ACTIONS_HPP
