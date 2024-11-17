#include "stringHelper.hpp"

std::string normalizePath(const std::string& s) {
    std::filesystem::path canonicalPath = std::filesystem::weakly_canonical(std::filesystem::path(s));
    return canonicalPath.make_preferred().string();
}

std::string relativeToRealPath(const std::string &executablePath, const char *s) {
    std::string r = normalizePath(std::filesystem::path(executablePath + "/" + std::string(s)).string());
    return r;
}

std::string toLowerCase(const std::string& input) {
    std::string result = input;
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) {
        return std::tolower(c);
    });
    return result;
}

std::string toUpperCase(const std::string& input) {
    std::string result = input;
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) {
        return std::toupper(c);
    });
    return result;
}
