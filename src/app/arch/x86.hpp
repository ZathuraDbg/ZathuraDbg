#include <utility>
#include <iostream>
#include <cstdint>
#include <cstdlib>
#include <unordered_map>
#include <unicorn/unicorn.h>
#include <vector>

extern std::unordered_map<std::string, std::pair<size_t, int>> x86RegInfoMap;
extern std::vector<std::string> x86Instructions;
extern std::string x86IPStr(uc_mode mode);
extern std::string x86SPStr(uc_mode mode);
extern int x86RegNameToConstant(const std::string &name);