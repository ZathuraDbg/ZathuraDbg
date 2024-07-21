#include "actions.hpp"

void startDebugging(){
    resetState();
    debugModeEnabled = true;
    LOG_DEBUG("Context is empty!");
    fileRunTask(1);
}

void restartDebugging(){
    resetState();
    fileRunTask(1);
}

void stepOverAction(){
    uint64_t ip;
    int lineNo;

    uc_context_restore(uc, context);
    ip = getRegister(getArchIPStr(codeInformation.mode)).second;
    std::string str = addressLineNoMap[std::to_string(ip)];

    if (!str.empty()){
        lineNo = std::atoi(str.c_str());
        breakpointLines.push_back(lineNo + 1);
        stepCode(0);
        continueOverBreakpoint = true;
    }
}

void stepInAction(){
    stepIn = true;
    stepCode(1);
    stepIn = false;
}

void debugPauseAction(){
    uc_context_save(uc, context);
    uc_emu_stop(uc);
}

void debugStopAction(){
    debugModeEnabled = false;
    resetState();
}
bool show = false;
void handleKeyboardInput(){
    if (enableDebugMode){
        startDebugging();
        enableDebugMode = false;
    }
    if (debugRestart){
        restartDebugging();
        debugRestart = false;
    }
    if (debugRun){
        resetState();
//      -1 = it will be computed later in the function below
        fileRunTask(-1);
        debugRun = false;
    }
    if (debugContinue){
        stepCode(0);
        debugContinue = false;
    }
    if (debugStepOver){
        stepOverAction();
        debugStepOver = false;
    }
    if (debugStepIn){
        stepInAction();
        debugStepIn = false;
    }
    if (debugPause){
        debugPauseAction();
        debugPause = false;
    }
    if (debugStop){
        debugStopAction();
        debugStop = false;
    }

    if (saveFile){
        LOG_INFO("File save requested!");
        fileSaveTask(selectedFile);
        saveFile = false;
    }
    if (openFile){
        LOG_INFO("File open dialog requested!");
        resetState();
        fileOpenTask(openFileDialog());
        openFile = false;
    }
    if (saveFileAs){
        LOG_INFO("File save as requested!");
        fileSaveAsTask(saveAsFileDialog());
        saveFileAs = false;
    }
    if (saveContextToFile){
        if (context == nullptr || uc == nullptr){
            return;
        }

        fileSaveUCContextAsJson(saveAsFileDialog());
    }
    if (fileLoadContext){
        fileLoadUCContextFromJson(openFileDialog());
        uint64_t rip;
        int lineNumber;

        uc_reg_read(uc, regNameToConstant("RIP"), &rip);
        std::string str =  addressLineNoMap[std::to_string(rip)];
        if (!str.empty()) {
            lineNumber = std::atoi(str.c_str());
            editor->HighlightDebugCurrentLine(lineNumber - 1);
        }
    }

    if (changeEmulationSettingsOpt){
        changeEmulationSettings();
    }
}