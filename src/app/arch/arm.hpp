#ifndef ZATHURA_ARM_HPP
#define ZATHURA_ARM_HPP
#include <string>
#include <unordered_map>
#include <unicorn/unicorn.h>

extern std::unordered_map<std::string, std::pair<size_t, int>> armRegInfoMap;
extern std::string armIPStr(uc_mode mode);
extern std::string arm64IPStr(uc_mode mode);
#endif
