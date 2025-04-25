#ifndef windows_hpp
#define windows_hpp
#define IMGUI_DEFINE_MATH_OPERATORS
#include "../tasks/editorTasks.hpp"
#include "../../../vendor/ordered-map/include/tsl/ordered_map.h"
#include "../../../vendor/log/clue.hpp"
#include "../integration/interpreter/interpreter.hpp"
#include "../../../vendor/imgui/misc/cpp/imgui_stdlib.h"
#include "../arch/arch.hpp"
#include <regex>
#include "../../vendor/tinyexpr/tinyexpr.h"
#include "../actions/actions.hpp"
#include "../actions/actions.hpp"
#include "../../utils/uiElements.h"

struct newMemEditWindowsInfo{
    MemoryEditor memEditor;
    uint64_t address{};
    size_t size{};
};

enum contextMenuOption {
    REGISTER_HIDDEN,
    LANES_TOGGLED,
    NORMAL_ACTION
};

typedef struct
{
    uint64_t start;
    uint64_t end;
    MemoryProtection perms;
} memoryMapInfo;

enum arch{
    x86 = 0,
    ARM,
    ARM64,
    RISCV,
    PowerPC
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
extern bool memoryMapsUI;

extern const uc_mode x86UCModes[];
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
extern bool stackArraysZeroed;
extern bool codeHasRun;
extern bool stepClickedOnce;
extern void registerWindow();
extern void updateRegs(bool useTempContext = false);
extern void consoleWindow();
extern void hexEditorWindow();
extern unsigned char zeroArr[0x1000];
extern uint64_t hexStrToInt(const std::string& val);
extern void stackEditorWindow();
extern std::vector<std::string> parseRegisters(std::string registerString);
extern MemoryEditor memoryEditorWindow;
extern void stackWriteFunc(ImU8* data, size_t offset, ImU8 delta);
extern void hexWriteFunc(ImU8* data, size_t off, ImU8 d);
extern MemoryEditor stackEditor;
extern int checkHexCharsCallback(ImGuiInputTextCallbackData* data);
extern const char* architectureStrings[];
bool showRequiredButton(const std::string& buttonName, bool state = false);
extern uint16_t getRegisterActualSize(std::string str);
extern MemoryEditor::fillRangeInfoT fillMemoryWithBytePopup();
extern void parseRegisterValueInput(const std::string& regName, const char *regValueFirst, const bool isBigReg);
extern void removeRegisterFromView(const std::string& reg, int regType = 1);
extern std::string getRegisterActualName(const std::string& regName);
extern bool updateRegistersOnLaneChange();
extern std::vector<memoryMapInfo> getMemoryMapping(uc_engine* uc);
extern void memoryMapWindow();
extern std::pair<size_t, size_t> infoPopup(const std::string& title = "", const std::string& sizeHint = "");
extern std::vector<newMemEditWindowsInfo> newMemEditWindows;
extern unsigned char* stackEditorData;
extern unsigned char* stackEditorTemp;
extern void cleanupStackEditor();
#endif