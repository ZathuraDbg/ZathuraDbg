#ifndef ZATHURA_UI_DIALOGHEADER_HPP
#define ZATHURA_UI_DIALOGHEADER_HPP
#define LOG_MODULE_NAME "Zathura"

#include <iostream>
#include <fstream>
#include <filesystem>
#include <tinyfiledialogs.h>
#include "../../../vendor/ImGuiColorTextEdit/TextEditor.h"
#include "../../../vendor/ImGuiColorTextEdit/TextEditor.h"
#include "../../utils/fonts.hpp"
#include "../../../vendor/imgui/imgui.h"
#include "../../../vendor/imgui/imgui_internal.h"
#include "../../../vendor/log/clue.hpp"

extern std::string selectedFile;
extern std::string openFileDialog();
extern std::string saveAsFileDialog();

#endif //ZATHURA_UI_DIALOGHEADER_HPP
