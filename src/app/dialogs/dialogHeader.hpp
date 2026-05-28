#ifndef ZATHURA_UI_DIALOGHEADER_HPP
#define ZATHURA_UI_DIALOGHEADER_HPP

#include <iostream>
#include <fstream>
#include <filesystem>
#include <tinyfiledialogs.h>
#include "../../utils/fonts.hpp"
#include "../../../vendor/imgui/imgui.h"
#include "../../../vendor/imgui/imgui_internal.h"
#include "../../utils/logger.hpp"

extern std::string selectedFile;
extern std::string openFileDialog();
extern std::string saveAsFileDialog();

#endif //ZATHURA_UI_DIALOGHEADER_HPP
