#ifndef ZATHURA_UI_APP_HPP
#define ZATHURA_UI_APP_HPP
#define IMGUI_DEFINE_MATH_OPERATORS
#include "../../imgui/imgui_internal.h"
#include "../../imgui/backends/imgui_impl_glfw.h"
#include "../../imgui/backends/imgui_impl_opengl3.h"
#include "../../imgui/misc/single_file/imgui_single_file.h"
#include <iostream>
#include <fstream>
#include "../../hex/hex.h"
#include "../../imgui/imgui.h"
#include "../../ImGuiColorTextEdit/TextEditor.h"
#include "../utils/fonts.hpp"
#include "../utils/layoutmanager.h"
#include <cstdio>
#include "../utils/style.h"
#define CONFIG_NAME "config"

extern void setupViewPort();

enum fonts{
    Default,
    SatoshiSmall,
    SatoshiBig,
    JetBrainsMono
};
extern void LoadIniFile();
extern void mainWindow();
extern TextEditor* editor;
extern void setupEditor();
extern void appMenuBar();
#endif //ZATHURA_UI_APP_HPP
