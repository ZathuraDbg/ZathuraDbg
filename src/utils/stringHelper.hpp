#ifndef ZATHURA_STRINGHELPER_HPP
#define ZATHURA_STRINGHELPER_HPP
#include <string>
#include <algorithm>
#include <filesystem>
extern std::string normalizePath(const std::string& s);
extern std::string relativeToRealPath(const std::string& executablePath, const char *s);
extern std::string toLowerCase(const std::string& input);
extern std::string toUpperCase(const std::string& input);
#endif //ZATHURA_STRINGHELPER_HPP
