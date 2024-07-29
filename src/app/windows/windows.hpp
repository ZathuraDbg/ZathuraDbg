#ifndef windows_hpp
#define windows_hpp
#define IMGUI_DEFINE_MATH_OPERATORS
#include "../tasks/editorTasks.hpp"
#include "../../../vendor/ordered-map/include/tsl/ordered_map.h"
#include "../../../vendor/log/clue.hpp"
#include "../integration/interpreter/interpreter.hpp"
#include "../../../vendor/imgui/misc/cpp/imgui_stdlib.h"
#include "../arch/arch.hpp"
#include <list>
#include "../../vendor/tinyexpr/tinyexpr.h"

struct newMemEditWindowsInfo{
    MemoryEditor memEditor;
    uint64_t address{};
    size_t size{};
};


enum arch{
    x86 = 0,
    ARM,
    RISCV
};

extern bool saveContextToFile;
extern bool fileLoadContext;
extern bool changeEmulationSettingsOpt;
extern bool toggleBreakpoint;
extern bool runSelectedCode;
extern bool goToDefinition;
extern bool openFile;
extern bool saveFile;
extern bool saveFileAs;
extern bool debugRestart;
extern bool debugStepIn;
extern bool debugStepOver;
extern bool debugContinue;
extern bool debugStop;
extern bool debugPause;
extern bool debugRun;
extern bool enableDebugMode;

extern const uc_mode x86UCModes[];
extern const uc_mode armUCModes[];
extern const char* x86ModeStr[];
extern const char* armModeStr[];
extern const cs_arch csArchs[];
extern const ks_mode x86KSModes[];
extern const cs_mode x86CSModes[];
extern const ks_mode armKSModes[];
extern const cs_mode armCSMOdes[];
extern const char* ksSyntaxOptStr[];
extern const ks_opt_value ksSyntaxOpts[];
extern tsl::ordered_map<std::string, std::string> registerValueMap;
extern void changeEmulationSettings();
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
extern int checkHexCharsCallback(ImGuiInputTextCallbackData* data);
extern const char* items[];
#endif