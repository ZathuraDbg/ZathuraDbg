#include <thread>
#include "actions.hpp"
#include "../integration/interpreter/interpreter.hpp"

void startDebugging(){
    LOG_INFO("Starting debugging...");

    resetState();
    if (!fileRunTask(1)) {
        LOG_ERROR("Unable to start debugging.");
        LOG_ERROR("fileRunTask failed!");
        return;
    }

    LOG_INFO("Debugging started successfully.");
    debugModeEnabled = true;
}

void restartDebugging(){
    LOG_INFO("Restarting debugging...");
    resetState();
    fileRunTask(1);
    LOG_INFO("Debugging restarted successfully.");
}

void stepOverAction(){
    LOG_INFO("Stepping over...");
    uc_context_restore(uc, context);
    const uint64_t instructionPointer = getRegister(getArchIPStr(codeInformation.mode)).registerValueUn.eightByteVal;
    const std::string lineNoStr = addressLineNoMap[std::to_string(instructionPointer)];

    if (!lineNoStr.empty()){
        const int lineNo = std::atoi(lineNoStr.c_str());

        breakpointMutex.lock();
        breakpointLines.push_back(lineNo + 1);
        breakpointMutex.unlock();
        stepCode(0);

        if (stepOverBPLineNo == lineNo){
            breakpointMutex.lock();
            LOG_DEBUG("Removing step over breakpoint line number: " << stepOverBPLineNo);
            const auto it = std::ranges::find(breakpointLines, stepOverBPLineNo);
            if (it!=breakpointLines.end()) {
                breakpointLines.erase(it);
            }
            breakpointMutex.unlock();
            stepOverBPLineNo = -1;
        }

        stepOverBPLineNo = lineNo + 1;
        LOG_INFO("Step over breakpoint line number: " << stepOverBPLineNo << " done");
        continueOverBreakpoint = true;
    }
}

void stepInAction(){
    LOG_INFO("Stepping in...");
    if (wasJumpAndStepOver){
        // workaround for the unicorn engine bug:
        stepIn = false;
        pauseNext = false;
        LOG_INFO("Stepping in done.");
        wasJumpAndStepOver = false;
        wasStepOver = false;
        debugStepOver = true;
        runActions();
        stepInBypassed = true;
        return;
    }
    stepIn = true;
    stepCode(1);
    stepIn = false;
    pauseNext = false;
    LOG_INFO("Stepping in done.");
}

bool debugPaused = false;
void debugPauseAction(){
    LOG_INFO("Pause action requested!");
    auto instructionPointer = getRegisterValue(getArchIPStr(codeInformation.mode), false);
    const std::string currentLineNo = addressLineNoMap[std::to_string(instructionPointer.eightByteVal)];
    const auto lineNumber = std::atoi(currentLineNo.c_str());
    editor->HighlightDebugCurrentLine(lineNumber - 1);
    debugPaused = true;
    uc_context_save(uc, context);
    uc_emu_stop(uc);
    LOG_INFO("Code paused successfully!");
}

void debugStopAction(){
    debugModeEnabled = false;
    resetState();
    LOG_INFO("Debugging stopped successfully.");
}

void debugToggleBreakpoint(){
    int line, _;
    editor->GetCursorPosition(line, _);

    auto breakpointIterator= (std::ranges::find(breakpointLines, line + 1));
    if (breakpointIterator != breakpointLines.end()){
        LOG_DEBUG("Removing the breakpoint at line: " <<  line);
        breakpointMutex.lock();
        breakpointLines.erase(breakpointIterator);
        breakpointMutex.unlock();
        editor->RemoveHighlight(line);
    }
    else{
        for (auto &pair: labelLineNoMapInternal){
            if (pair.second == (line+1)){
                line += 1;
            }
        }

        LOG_DEBUG("Adding the breakpoint at line: " << line);
        breakpointLines.push_back(line + 1);
        editor->HighlightBreakpoints(line);
    }
}

bool debugAddBreakpoint(const int lineNum){
    LOG_DEBUG("Adding breakpoint on the line " << lineNum);

    const auto breakpointLineNo = (std::ranges::find(breakpointLines, lineNum + 1));
    if (breakpointLineNo != breakpointLines.end()){
        LOG_DEBUG("Breakpoint already exists, skipping...");
        return false;
    }
    else{
        breakpointLines.push_back(lineNum + 1);
        editor->HighlightBreakpoints(lineNum);
        LOG_DEBUG("Breakpoint added successfully!");
    }

    return true;
}

bool debugRemoveBreakpoint(const int lineNum){
    LOG_DEBUG("Removing the breakpoint at " << lineNum);
    auto breakpointIter = (std::ranges::find(breakpointLines, lineNum + 1));

    if (breakpointIter == breakpointLines.end()){
        LOG_DEBUG("No breakpoint exists at line no. " << lineNum);
        return false;
    }
    else{
        breakpointMutex.lock();
        breakpointLines.erase(breakpointIter);
        breakpointMutex.unlock();
        editor->RemoveHighlight(lineNum);
        LOG_DEBUG("Removed breakpoint at line no. " << lineNum);
    }

    return true;
}

void debugRunSelectionAction(){
    LOG_INFO("Running selected code...");
    std::stringstream selectedAsmText(editor->GetSelectedText());

    if (!selectedAsmText.str().empty()) {
        const std::string bytes = getBytes(selectedAsmText);

        if (!bytes.empty()) {
            debugRun = true;
            runTempCode(bytes, countValidInstructions(selectedAsmText));
            debugRun = false;
            LOG_INFO("Selection ran successfully!");
        }
        else {
            LOG_ERROR("Unable to run selected code because bytes were not returned.");
        }
    }
    else {
        LOG_INFO("Nothing was selected to run, skipping.");
    }
}

void debugContinueAction(const bool skipBP){
    LOG_DEBUG("Continuing debugging...");

    if (std::ranges::find(breakpointLines, stepOverBPLineNo) != breakpointLines.end()){
        const auto it = std::ranges::find(breakpointLines, tempBPLineNum);
        if (it != breakpointLines.end()) {
            breakpointMutex.lock();
            breakpointLines.erase(it);
            breakpointMutex.unlock();
        }
        stepOverBPLineNo = -1;
    }

    skipBreakpoints = skipBP;
    std::thread stepCodeThread(stepCode, 0);
    stepCodeThread.detach();
}

void runActions(){
    if (enableDebugMode){
        startDebugging();
        enableDebugMode = false;
    }
    if (debugModeEnabled) {
        if (debugRestart){
            if (isCodeRunning){
                debugPauseAction();
            }
            restartDebugging();
            debugRestart = false;
        }
        if (debugContinue){
  //        debugContinueAction();
            std::thread continueActionThread(debugContinueAction, false);
            continueActionThread.detach();
            debugContinue = false;
        }
        if (debugStepOver){
            if (isCodeRunning){
                debugStepOver = false;
                return;
            }

            // stepOverAction();


            wasStepOver = true;
            std::thread stepOverActionThread(stepOverAction);
            stepOverActionThread.detach();
            debugStepOver = false;
        }
        else if (debugStepIn){
            if (isCodeRunning){
                debugStepIn = false;
                return;
            }

            stepInAction();

//      should executing only one instruction really require a separate thread?
//      std::thread stepInActionThread(stepInAction);
//      stepInActionThread.detach();

            debugStepIn = false;
        }
        if (debugPause){
            debugPauseAction();
            debugPause = false;
        }
        else if (debugStop){
            debugStopAction();
            debugStop = false;
        }
    }

    if (runUntilHere){
        int _;
        editor->GetCursorPosition(runUntilLine, _);
        runUntilLine++;
        if (!debugModeEnabled){
            startDebugging();
        }
        std::thread continueActionThread(debugContinueAction, false);
        continueActionThread.detach();
        runUntilHere = false;
    }
    if (debugRun){
        if (isCodeRunning){
            debugRun = false;
            return;
        }

        skipBreakpoints = true;
        if ((resetState()) && (fileRunTask(-1))){
        }
        else {
            skipBreakpoints = false;
        }

        debugRun = false;
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
        LOG_INFO("Saving file to context requested!");
        if (context == nullptr || uc == nullptr){
            saveContextToFile = false;
            return;
        }

        fileSaveUCContextAsJson(saveAsFileDialog());
                    saveContextToFile = false;
    }
    if (fileLoadContext){
        LOG_INFO("Saving file to context requested!");
        fileLoadUCContextFromJson(openFileDialog());
        uint64_t ip;

        uc_reg_read(uc, regNameToConstant(getArchIPStr(codeInformation.mode)), &ip);
        const std::string str =  addressLineNoMap[std::to_string(ip)];
        if (!str.empty()) {
            const int lineNumber = std::atoi(str.c_str());
            editor->HighlightDebugCurrentLine(lineNumber - 1);
        }

        fileLoadContext = false;
    }

    if (changeEmulationSettingsOpt){
        LOG_INFO("Change in emulation settings requested!");
        changeEmulationSettings();
    }

    if (toggleBreakpoint){
        debugToggleBreakpoint();
        toggleBreakpoint = false;
    }

    if (runSelectedCode){
        debugRunSelectionAction();
        runSelectedCode = false;
    }

    if (goToDefinition){
        LOG_INFO("Going to label's definiton...");
        editor->SelectLabelDefinition(false);
        goToDefinition = false;
    }
}
