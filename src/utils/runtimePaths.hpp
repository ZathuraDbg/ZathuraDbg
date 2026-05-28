#ifndef ZATHURA_RUNTIMEPATHS_HPP
#define ZATHURA_RUNTIMEPATHS_HPP

#include <filesystem>
#include <string>
#include <vector>

namespace Zathura::RuntimePaths {

std::filesystem::path configDir();
std::filesystem::path logDir();
std::filesystem::path configFile();
std::filesystem::path logFile();
std::vector<std::filesystem::path> legacyConfigFiles(const std::filesystem::path &installDir);

bool ensureUserDirectories(std::string *errorMessage = nullptr);
bool migrateConfigIfNeeded(const std::filesystem::path &installDir, std::string *errorMessage = nullptr);

}

#endif // ZATHURA_RUNTIMEPATHS_HPP
