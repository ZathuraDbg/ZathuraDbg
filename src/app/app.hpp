#ifndef ZATHURA_UI_APP_HPP
#define ZATHURA_UI_APP_HPP
#define IMGUI_DEFINE_MATH_OPERATORS
#define LOG_MODULE_NAME "Zathura"

extern bool isRunning;
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


extern void setupViewPort();
void appMenuBar();
extern void manageShortcuts();
extern void LoadIniFile();
extern bool setupButtons();
extern void mainWindow();
extern void setupEditor();
#endif //ZATHURA_UI_APP_HPP
