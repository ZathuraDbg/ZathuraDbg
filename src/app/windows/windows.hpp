#ifndef windows_hpp
#define windows_hpp
#include "../tasks/editorTasks.hpp"
#include "../../../vendor/ordered-map/include/tsl/ordered_map.h"
#include "../../../vendor/log/clue.hpp"
#include "../integration/interpreter/interpreter.hpp"
#include "../../../vendor/imgui/misc/cpp/imgui_stdlib.h"
#include <list>

extern tsl::ordered_map<std::string, std::string> registerValueMap;
extern std::unordered_map<std::string, std::string> tempRegisterValueMap;
extern bool codeHasRun;
extern bool stepClickedOnce;
extern void registerWindow();
extern void updateRegs(bool useTempContext = false);
extern void consoleWindow();
extern void hexEditorWindow();
extern uint64_t hexStrToInt(const std::string& val);
extern void stackEditorWindow();
extern std::vector<std::string> parseRegisters(std::string registerString);
extern MemoryEditor memoryEditorWindow;
extern void stackWriteFunc(ImU8* data, size_t off, ImU8 d);
extern void hexWriteFunc(ImU8* data, size_t off, ImU8 d);
extern MemoryEditor stackEditor;
extern bool windowCreated;
#endif