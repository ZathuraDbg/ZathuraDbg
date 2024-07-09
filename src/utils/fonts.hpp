#ifndef FONTS
#define FONTS

#include "../../imgui/imgui_internal.h"
#include "../../imgui/backends/imgui_impl_glfw.h"
#include "../../imgui/backends/imgui_impl_opengl3.h"
#include "../../imgui/misc/single_file/imgui_single_file.h"
#include <iostream>
#include <fstream>
#include "../../hex/hex.h"
#include "../../imgui/imgui.h"
#include "iconfont.h"
#include "../../ImGuiColorTextEdit/TextEditor.h"
#include <cstdio>

enum fonts{
    Default,
    Satoshi16,
    Satoshi18,
    JetBrainsMono20,
    RubikRegular16,
    SatoshiBold18,
    SatoshiMedium18,
    SatoshiRegular16,
    JetBrainsMono24
};
extern ImGuiIO& setupIO();

#endif