#ifndef ZATHURA_UI_EDITORTASKS_HPP
#define ZATHURA_UI_EDITORTASKS_HPP
#include "../dialogs/dialogHeader.hpp"
#include "../integration/interpreter/interpreter.hpp"
#include "../../vendor/ImGuiColorTextEdit/TextEditor.h"

extern TextEditor* editor;
extern bool writeEditorToFile(const std::string& filePath);
extern bool readFileIntoEditor(const std::string& filePath);
extern void pasteCallback(std::string clipboardText);
extern int labelCompletionCallback(ImGuiInputTextCallbackData* data);
extern void createLabelLineMapCallback(std::map<std::string, int>& labelVector);
extern std::pair<int, int> parseStrIntoCoordinates(std::string& popupInput);
#endif //ZATHURA_UI_EDITORTASKS_HPP
