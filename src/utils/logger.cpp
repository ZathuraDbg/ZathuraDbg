#include "logger.hpp"

#include "runtimePaths.hpp"

#include <fstream>
#include <iostream>
#include <mutex>
#include <system_error>

namespace Zathura::Logger {
namespace {

std::mutex s_logMutex;
std::filesystem::path s_logFilePath;
bool s_reportedWriteError = false;

void appendError(std::string *errorMessage, const std::string &message) {
    if (errorMessage == nullptr) {
        return;
    }

    if (!errorMessage->empty()) {
        *errorMessage += "\n";
    }
    *errorMessage += message;
}

std::filesystem::path activeLogFilePath() {
    if (s_logFilePath.empty()) {
        s_logFilePath = RuntimePaths::logFile();
    }

    return s_logFilePath;
}

}

bool initialize(const std::filesystem::path &path, std::string *errorMessage) {
    std::lock_guard lock(s_logMutex);
    s_logFilePath = path;

    std::error_code error;
    std::filesystem::create_directories(s_logFilePath.parent_path(), error);
    if (error) {
        appendError(errorMessage, "Failed to create log directory '" + s_logFilePath.parent_path().string() + "': " + error.message());
        return false;
    }

    if (!std::filesystem::is_directory(s_logFilePath.parent_path(), error) || error) {
        appendError(errorMessage, "Log directory is not usable: '" + s_logFilePath.parent_path().string() + "'");
        return false;
    }

    return true;
}

std::filesystem::path logFilePath() {
    std::lock_guard lock(s_logMutex);
    return activeLogFilePath();
}

void write(const std::string &text) {
    std::lock_guard lock(s_logMutex);

    const auto path = activeLogFilePath();
    std::error_code error;
    std::filesystem::create_directories(path.parent_path(), error);
    if (error) {
        if (!s_reportedWriteError) {
            std::cerr << "Failed to create log directory '" << path.parent_path().string()
                      << "': " << error.message() << '\n';
            s_reportedWriteError = true;
        }
        return;
    }

    std::ofstream os(path, std::ios_base::app);
    if (!os.is_open()) {
        if (!s_reportedWriteError) {
            std::cerr << "Failed to open log file '" << path.string() << "' for writing.\n";
            s_reportedWriteError = true;
        }
        return;
    }

    os << text;
}

}
