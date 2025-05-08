#ifndef ZATHURA_ARM_HPP
#define ZATHURA_ARM_HPP
#include <string>
#include <unordered_map>
#include <vector>
#include <utility>
#include <unordered_set>
#include "arch.hpp"
#include "icicle.h"

// ARM register info map
extern std::unordered_map<std::string, size_t> armRegInfoMap;
extern std::unordered_map<std::string, size_t> aarch64RegInfoMap;
// Default registers to show in the UI
extern std::vector<std::string> armDefaultShownRegs;
extern std::vector<std::string> aarch64DefaultShownRegs;

// Helper functions
extern std::string armIPStr(int mode);
extern std::string aarch64IPStr(int mode);
extern std::pair<std::string, std::string> armSBPStr(int mode);
extern std::pair<std::string, std::string> aarch64SBPStr(int mode);
extern bool armIsRegisterValid(const std::string& reg);
extern bool aarch64IsRegisterValid(const std::string& reg);
extern void armModeUpdateCallback(int arch);
extern void aarch64ModeUpdateCallback();

#endif //ZATHURA_ARM_HPP
