#ifndef windows_hpp
#define windows_hpp
#include "../tasks/editorTasks.hpp"
#include "../../../vendor/ordered-map/include/tsl/ordered_map.h"
#include "../../../vendor/imgui/misc/cpp/imgui_stdlib.h"
#include "../../../vendor/log/clue.hpp"
#include "../integration/interpreter/interpreter.hpp"
#include <list>

extern tsl::ordered_map<std::string, std::string> registerValueMap;

extern void registerWindow();
extern void consoleWindow();
extern void hexEditorWindow();
extern void stackEditorWindow();
#endif