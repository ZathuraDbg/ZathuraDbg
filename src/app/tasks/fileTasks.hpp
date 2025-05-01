#ifndef fileTasks
#define fileTasks

#include "../dialogs/dialogHeader.hpp"
#include "editorTasks.hpp"
#include "../integration/interpreter/interpreter.hpp"
#include <unicorn/unicorn.h>
#include <filesystem>

extern bool serializeState();
extern bool deserializeState();
extern std::filesystem::path getTemporaryPath();
bool fileOpenTask(const std::string& fileName);
void fileSaveAsTask(const std::string &fileName);
void fileSaveTask(const std::string &fileName);
extern bool fileRunTask(const bool& execCode);
#endif // !fileTasks
