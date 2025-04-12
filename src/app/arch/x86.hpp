#include <utility>
#include <iostream>
#include <cstdint>
#include <cstdlib>
#include <unordered_map>
#include <unicorn/unicorn.h>
#include <vector>
extern std::vector<std::string> x86DefaultShownRegs;
extern std::unordered_map<std::string, size_t> x86RegInfoMap;
extern std::vector<std::string> x86ArchInstructions;
extern std::string x86IPStr(uc_mode mode);
extern std::pair<std::string, std::string> x86SBPStr(uc_mode mode);
extern bool x86IsRegisterValid(const std::string& reg);
extern void x86ModeUpdateCallback();