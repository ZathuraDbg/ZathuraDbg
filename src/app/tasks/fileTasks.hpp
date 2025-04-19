#ifndef fileTasks
#define fileTasks

#include "../dialogs/dialogHeader.hpp"
#include "editorTasks.hpp"
#include "../integration/interpreter/interpreter.hpp"
#include <unicorn/unicorn.h>
#include <filesystem>

extern std::filesystem::path getTemporaryPath();
bool fileOpenTask(const std::string& fileName);
void fileSaveAsTask(const std::string &fileName);
void fileSaveTask(const std::string &fileName);
extern bool fileRunTask(const bool& execCode);
extern void fileSaveUCContextAsJson(const std::string& jsonFilename);
extern void fileLoadUCContextFromJson(const std::string& jsonFilename);
#endif // !fileTasks
