#ifndef ZATHURA_UI_APP_HPP
#define ZATHURA_UI_APP_HPP
#define IMGUI_DEFINE_MATH_OPERATORS
#define LOG_MODULE_NAME "Zathura"
#include <cstdio>
#include <string>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <charconv>
#include <tinyfiledialogs.h>
#include "../../vendor/log/clue.hpp"
#include <tsl/ordered_map.h>
#include <unicorn/unicorn.h>
#include "../utils/style.h"
#include "../utils/fonts.hpp"
#include "../../vendor/imgui/imgui.h"
#include "tasks/fileTasks.hpp"
#include "tasks/editorTasks.hpp"
#include "dialogs/dialogHeader.hpp"
#include "../utils/layoutmanager.h"
#include "../../vendor/imgui/imgui_internal.h"
#include "../../vendor/ImGuiColorTextEdit/TextEditor.h"
#include "../../vendor/imgui/backends/imgui_impl_glfw.h"
#include "../../vendor/imgui/backends/imgui_impl_opengl3.h"
#include "../../vendor/imgui/misc/single_file/imgui_single_file.h"
#include "../../vendor/hex/hex.h"
#include "integration/interpreter/interpreter.hpp"
#include "windows/windows.hpp"
#include "../../vendor/json/json.hpp"
#include <capstone/capstone.h>
#include "actions/actions.hpp"
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <http.hpp>
using json = nlohmann::json;
constexpr std::string VERSION = "1.0";
#define CONFIG_NAME "config"

std::string parseVals(std::string val);
void setupViewPort();
void appMenuBar();
void manageShortcuts();
void loadIniFile();
bool setupButtons();
void mainWindow();
void setupEditor();
extern  std::string getDataToCopy(const std::stringstream &selectedAsmText, const bool asArray);
extern bool lineNumbersShown;
extern float frameRate;
extern std::string executablePath;
extern bool isRunning;
extern TextEditor::LanguageDefinitionId currentDefinitionId;
extern std::string currentVersion;
extern std::string getLatestVersion();
#endif //ZATHURA_UI_APP_HPP
