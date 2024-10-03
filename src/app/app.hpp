#ifndef ZATHURA_UI_APP_HPP
#define ZATHURA_UI_APP_HPP
#define IMGUI_DEFINE_MATH_OPERATORS
#define LOG_MODULE_NAME "Zathura"

#include <cstdio>
#include <string>
#include <fstream>
#include <iostream>
#include <filesystem>
#include "../../vendor/code/tinyfiledialogs.h"
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
#include "../../vendor/imgui/backends/imgui_impl_glfw.h"
#include "../../vendor/imgui/backends/imgui_impl_opengl3.h"
#include "../../vendor/imgui/misc/single_file/imgui_single_file.h"
#include "../../vendor/hex/hex.h"
#include "integration/interpreter/interpreter.hpp"
#include "windows/windows.hpp"
#include "nlohmann/json.hpp"
#include <capstone/capstone.h>
#include "actions/actions.hpp"
using json = nlohmann::json;
#define CONFIG_NAME "config"

//extern ImU32 bgColorFn(const ImU8* data, size_t off);
//extern void interactFn(const ImU8* data, size_t off);
bool showRequiredButton(const std::string& buttonName, bool state = false);
std::string parseVals(std::string val);
void setupViewPort();
void appMenuBar();
void manageShortcuts();
void LoadIniFile();
bool setupButtons();
void mainWindow();
void setupEditor();

extern float frameRate;
extern std::string executablePath;
extern bool isRunning;

#endif //ZATHURA_UI_APP_HPP
