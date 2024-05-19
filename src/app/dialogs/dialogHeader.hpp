#ifndef ZATHURA_UI_DIALOGHEADER_HPP
#define ZATHURA_UI_DIALOGHEADER_HPP

#include "../../utils/filedialog.h"
#include "../../../vendor/ImGuiColorTextEdit/TextEditor.h"
#include "../../utils/fonts.hpp"
#include "../../../vendor/imgui/imgui.h"
#include "../../../vendor/imgui/imgui_internal.h"
#include <iostream>
#include <fstream>

extern std::string selectedFile;
extern std::string openFileDialog();
extern std::string saveAsFileDialog();

#endif //ZATHURA_UI_DIALOGHEADER_HPP
