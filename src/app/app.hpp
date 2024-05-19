#ifndef ZATHURA_UI_APP_HPP
#define ZATHURA_UI_APP_HPP
#define IMGUI_DEFINE_MATH_OPERATORS

#include <cstdio>
#include <string>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <tsl/ordered_map.h>
#include "../utils/style.h"
#include "../utils/fonts.hpp"
#include "../../imgui/imgui.h"
#include "tasks/fileTasks.hpp"
#include "tasks/editorTasks.hpp"
#include "dialogs/dialogHeader.hpp"
#include "../utils/layoutmanager.h"
#include "../../imgui/imgui_internal.h"
#include "../../imgui/backends/imgui_impl_glfw.h"
#include "../../imgui/backends/imgui_impl_opengl3.h"
#include "../../imgui/misc/single_file/imgui_single_file.h"
#include "../../hex/hex.h"
#include "windows/windows.hpp"
//#include "../../ImGuiColorTextEdit/TextEditor.h"

#define CONFIG_NAME "config"

extern void setupViewPort();
void setupButtons();
void appMenuBar();

enum fonts{
    Default,
    SatoshiSmall,
    SatoshiBig,
    JetBrainsMono
};
extern void LoadIniFile();

extern void appMenuBar();
extern void setupButtons();
extern void mainWindow();
extern void setupEditor();
#endif //ZATHURA_UI_APP_HPP
