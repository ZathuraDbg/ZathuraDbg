#include "runtimePaths.hpp"

#include <cstdlib>
#include <system_error>

namespace Zathura::RuntimePaths {
namespace {

constexpr const char *APP_DIR_NAME = "ZathuraDbg";
constexpr const char *CONFIG_FILE_NAME = "config.zlyt";
constexpr const char *LOG_FILE_NAME = "Zathura.zlog";

std::filesystem::path pathFromEnv(const char *name) {
    if (const char *value = std::getenv(name); value != nullptr && value[0] != '\0') {
        return std::filesystem::path(value);
    }

    return {};
}

std::filesystem::path homeDir() {
#ifdef _WIN32
    return pathFromEnv("USERPROFILE");
#else
    return pathFromEnv("HOME");
#endif
}

std::filesystem::path fallbackBase() {
    const auto home = homeDir();
    if (!home.empty()) {
        return home;
    }

    std::error_code error;
    const auto temp = std::filesystem::temp_directory_path(error);
    if (!error && !temp.empty()) {
        return temp;
    }

    return ".";
}

void appendError(std::string *errorMessage, const std::string &message) {
    if (errorMessage == nullptr) {
        return;
    }

    if (!errorMessage->empty()) {
        *errorMessage += "\n";
    }
    *errorMessage += message;
}

bool createDirectory(const std::filesystem::path &path, const char *description, std::string *errorMessage) {
    std::error_code error;
    std::filesystem::create_directories(path, error);
    if (error) {
        appendError(errorMessage, std::string("Failed to create ") + description + " directory '" + path.string() + "': " + error.message());
        return false;
    }

    if (!std::filesystem::is_directory(path, error) || error) {
        appendError(errorMessage, std::string("The ") + description + " path is not a usable directory: '" + path.string() + "'");
        return false;
    }

    return true;
}

}

std::filesystem::path configDir() {
#ifdef _WIN32
    auto base = pathFromEnv("APPDATA");
    if (base.empty()) {
        base = fallbackBase() / "AppData" / "Roaming";
    }
    return base / APP_DIR_NAME;
#elif defined(__APPLE__)
    return fallbackBase() / "Library" / "Application Support" / APP_DIR_NAME;
#else
    auto base = pathFromEnv("XDG_CONFIG_HOME");
    if (base.empty()) {
        base = fallbackBase() / ".config";
    }
    return base / APP_DIR_NAME;
#endif
}

std::filesystem::path logDir() {
#ifdef _WIN32
    auto base = pathFromEnv("LOCALAPPDATA");
    if (base.empty()) {
        base = fallbackBase() / "AppData" / "Local";
    }
    return base / APP_DIR_NAME / "Logs";
#elif defined(__APPLE__)
    return fallbackBase() / "Library" / "Logs" / APP_DIR_NAME;
#else
    auto base = pathFromEnv("XDG_STATE_HOME");
    if (base.empty()) {
        base = fallbackBase() / ".local" / "state";
    }
    return base / APP_DIR_NAME;
#endif
}

std::filesystem::path configFile() {
    return configDir() / CONFIG_FILE_NAME;
}

std::filesystem::path logFile() {
    return logDir() / LOG_FILE_NAME;
}

std::vector<std::filesystem::path> legacyConfigFiles(const std::filesystem::path &installDir) {
    return {
        installDir / CONFIG_FILE_NAME,
    };
}

bool ensureUserDirectories(std::string *errorMessage) {
    const bool configOk = createDirectory(configDir(), "config", errorMessage);
    const bool logOk = createDirectory(logDir(), "log", errorMessage);
    return configOk && logOk;
}

bool migrateConfigIfNeeded(const std::filesystem::path &installDir, std::string *errorMessage) {
    const auto target = configFile();
    std::error_code error;
    if (std::filesystem::exists(target, error)) {
        return true;
    }
    if (error) {
        appendError(errorMessage, "Failed to inspect config file '" + target.string() + "': " + error.message());
        return false;
    }

    if (!createDirectory(target.parent_path(), "config", errorMessage)) {
        return false;
    }

    for (const auto &candidate : legacyConfigFiles(installDir)) {
        if (!candidate.empty() && candidate != target && std::filesystem::exists(candidate, error)) {
            std::filesystem::copy_file(candidate, target, std::filesystem::copy_options::none, error);
            if (!error) {
                return true;
            }

            appendError(errorMessage, "Failed to migrate config from '" + candidate.string() + "' to '" + target.string() + "': " + error.message());
            return false;
        }

        if (error) {
            appendError(errorMessage, "Failed to inspect legacy config file '" + candidate.string() + "': " + error.message());
            return false;
        }
    }

    return true;
}

}
