#ifndef ZATHURA_UI_EDITORTASKS_HPP
#define ZATHURA_UI_EDITORTASKS_HPP
#include "../dialogs/dialogHeader.hpp"
#include "../../../vendor/ImGuiColorTextEdit/TextEditor.h"

extern TextEditor* editor;
extern bool writeEditorToFile(const std::string& filePath);
extern bool readFileIntoEditor(const std::string& filePath);
extern int labelCompletionCallback(ImGuiInputTextCallbackData* data);
#endif //ZATHURA_UI_EDITORTASKS_HPP
