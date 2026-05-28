#ifndef ZATHURA_LOGGER_HPP
#define ZATHURA_LOGGER_HPP

#include <filesystem>
#include <sstream>
#include <string>

#define LOG_MODULE_NAME "Zathura"
#define ZATHURA_ALLOW_DIRECT_CLUE_INCLUDE

#define clue_LOG_EXPRESSION(severity, expr) \
    do { \
        if (clue_is_active_build(severity)) { \
            if (clue_is_active(severity)) { \
                std::ostringstream zathuraLogStream; \
                zathuraLogStream << clue::now_text() << std::setw(clue_LOG_PREFIX_WIDTH) << \
                    clue::to_severity_text(severity) << clue::to_module_text(clue_LOG_MODULE_NAME) << \
                    ": " << expr << "\n"; \
                Zathura::Logger::write(zathuraLogStream.str()); \
            } \
        } \
    } while (clue::is_true(false))

#include "../../vendor/log/clue.hpp"

namespace Zathura::Logger {

bool initialize(const std::filesystem::path &path, std::string *errorMessage = nullptr);
std::filesystem::path logFilePath();
void write(const std::string &text);

}

#endif // ZATHURA_LOGGER_HPP
