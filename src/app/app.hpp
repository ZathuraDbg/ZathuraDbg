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
#include <cstdio>
extern void setupViewPort();

extern ImVec4 hexToImVec4(const char* hex);
extern void mainWindow();
extern TextEditor* editor;
extern void setupEditor();
extern ImGuiIO& setupIO();
extern void appMenuBar();
extern void SetupImGuiStyle();
#endif //ZATHURA_UI_APP_HPP
