#ifndef ZATHURA_ACTIONS_HPP
#define ZATHURA_ACTIONS_HPP
#include "../app.hpp"
extern void runActions();
extern void startDebugging();
extern void debugContinueAction(bool skipBP = false);
extern bool debugAddBreakpoint(int lineNum);
//#include "../app.hpp"
#endif //ZATHURA_ACTIONS_HPP
