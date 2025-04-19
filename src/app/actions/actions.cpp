#include <thread>
#include <condition_variable>
#include <functional>
#include "actions.hpp"
#include "../integration/interpreter/interpreter.hpp"

std::mutex uiUpdateMutex;
bool pendingUIUpdate = false;
int pendingHighlightLine = -1;

void executeInBackground(std::function<void()> func) {
    std::thread([func]() {
        func();
    }).detach();
}

void safeHighlightLine(int lineNo) {
    std::lock_guard<std::mutex> lock(uiUpdateMutex);
    pendingUIUpdate = true;
    pendingHighlightLine = lineNo;
}

void processUIUpdates() {
    std::lock_guard<std::mutex> lock(uiUpdateMutex);
    if (pendingUIUpdate) {
        if (pendingHighlightLine >= 0) {
            editor->HighlightDebugCurrentLine(pendingHighlightLine);
        }
        pendingUIUpdate = false;
    }
}

void startDebugging(){
    LOG_INFO("Starting debugging...");

    // Reset isDebugReady flag before starting setup
    {
        std::lock_guard<std::mutex> lk(debugReadyMutex);
        isDebugReady = false;
    }

    // Execute setup in a background thread to prevent UI freezing
    executeInBackground([]{
        if (!fileRunTask(false)) {
            LOG_ERROR("Unable to start debugging.");
            LOG_ERROR("fileRunTask failed!");
            // Ensure we don't deadlock if setup failed
            {
                std::lock_guard<std::mutex> lk(debugReadyMutex);
                isDebugReady = true; // Signal ready (even on failure) to unblock any waiters
            }
            debugReadyCv.notify_all();
            return;
        }

        // Note: preExecutionSetup should now signal isDebugReady and notify
        LOG_INFO("Debugging initialization sequence completed in background thread");
        debugModeEnabled = true;
    });
    
    // debugActionsMutex.unlock();
}

void restartDebugging(){
    // debugActionsMutex.lock();
    LOG_INFO("Restarting debugging...");
    
    executeInBackground([]{
        resetState();
        fileRunTask(false);
        LOG_INFO("Debugging restarted successfully.");
    });
    
    // debugActionsMutex.unlock();
}


void stepOverAction(){
    // debugActionsMutex.lock();
    LOG_INFO("Step over requested...");

    executeInBackground([]{
        // Wait until debugging state is fully ready
        {
            std::unique_lock<std::mutex> lk(debugReadyMutex);
            debugReadyCv.wait(lk, []{ return isDebugReady; });
        }
        LOG_DEBUG("Debug state confirmed ready, proceeding with step over.");

        const std::string lineNoStr = addressLineNoMap[std::to_string(icicle_get_pc(icicle))];

        if (!lineNoStr.empty()){
            const int lineNo = std::atoi(lineNoStr.c_str());

            breakpointMutex.lock();
            auto bpLineNoAddr = lineNoToAddress(lineNo + 1);
            icicle_add_breakpoint(icicle, bpLineNoAddr);
            breakpointLines.push_back(lineNo + 1); // Track the temporary breakpoint
            breakpointMutex.unlock();

            // Run until the next line (or breakpoint)
            executeCode(icicle, 0); // Use executeCode which handles breakpoints

            // Update UI with new position
            if (!executionComplete) {
                const std::string newLineStr = addressLineNoMap[std::to_string(icicle_get_pc(icicle))];
                if (!newLineStr.empty()) {
                    int newLineNo = std::atoi(newLineStr.c_str());
                    safeHighlightLine(newLineNo - 1);
                }
            }

            // Attempt to remove the temporary breakpoint
            breakpointMutex.lock();
            icicle_remove_breakpoint(icicle, bpLineNoAddr);
            auto it = std::ranges::find(breakpointLines, lineNo + 1);
            if (it != breakpointLines.end()) {
                 breakpointLines.erase(it);
                 LOG_DEBUG("Removed step over breakpoint at line: " << lineNo + 1);
            }
            breakpointMutex.unlock();

            // The old logic seems complex and potentially incorrect, replacing with simpler execute
            stepOverBPLineNo = -1; // Clear any leftover state
            LOG_INFO("Step over completed.");
            continueOverBreakpoint = false; // Reset this flag
        }
        else {
            LOG_WARNING("Could not get current line number for step over.");
        }
    });
    
    // debugActionsMutex.unlock();
}

void stepInAction(){
    // debugActionsMutex.lock();
    LOG_INFO("Stepping in requested...");

    executeInBackground([]{
        // Wait until debugging state is fully ready
        {
            std::unique_lock<std::mutex> lk(debugReadyMutex);
            debugReadyCv.wait(lk, []{ return isDebugReady; });
        }
        LOG_DEBUG("Debug state confirmed ready, proceeding with step in.");

        stepIn = true; // Flag likely unused now, but keep for consistency
        stepCode(1);   // Use the synchronized stepCode function
        
        // Update UI after step is complete
        if (!executionComplete) {
            const std::string lineNoStr = addressLineNoMap[std::to_string(icicle_get_pc(icicle))];
            if (!lineNoStr.empty()) {
                int lineNo = std::atoi(lineNoStr.c_str());
                safeHighlightLine(lineNo - 1);
            }
        }
        
        stepIn = false;
        pauseNext = false; // Reset flag
        LOG_INFO("Stepping in done.");
    });
    
    // debugActionsMutex.unlock();
}

bool debugPaused = false;
void debugPauseAction(){
    LOG_INFO("Pause action requested!");
    
    executeInBackground([]{
        auto instructionPointer = getRegisterValue(archIPStr);
        const std::string currentLineNo = addressLineNoMap[std::to_string(instructionPointer.eightByteVal)];
        const auto lineNumber = std::atoi(currentLineNo.c_str());
        safeHighlightLine(lineNumber - 1);
        debugPaused = true;
        saveICSnapshot(icicle);
        LOG_INFO("Code paused successfully!");
    });
}

void debugStopAction(){
    // debugActionsMutex.lock();
    debugModeEnabled = false;
    resetState();
    LOG_INFO("Debugging stopped successfully.");
    // debugActionsMutex.unlock();
}

void debugToggleBreakpoint(){
    int line, _;
    editor->GetCursorPosition(line, _);

    // this call will return false if the breakpoint was not found
    const auto isBreakpointRemoved = removeBreakpointFromLineNo(line + 1);
    if (isBreakpointRemoved){
        LOG_DEBUG("Removing the breakpoint at line: " <<  line);
        editor->RemoveHighlight(line);
    }
    else{
        LOG_DEBUG("Adding the breakpoint at line: " << line);
        addBreakpointToLine(line);
        editor->HighlightBreakpoints(line);
    }
}

bool debugAddBreakpoint(const int lineNum){
    LOG_DEBUG("Adding breakpoint on the line " << lineNum);
    breakpointMutex.lock();

    const auto breakpointLineNo = (std::ranges::find(breakpointLines, lineNum + 1));
    if (breakpointLineNo != breakpointLines.end()){
        LOG_DEBUG("Breakpoint already exists, skipping...");
        breakpointMutex.unlock();
        return false;
    }
    else{
        addBreakpointToLine(lineNum);
        editor->HighlightBreakpoints(lineNum);
        LOG_DEBUG("Breakpoint added successfully!");
    }

    breakpointMutex.unlock();
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
    std::string selectedText = editor->GetSelectedText();

    if (!selectedText.empty()) {
        executeInBackground([selectedText]() {
            std::stringstream selectedAsmText(selectedText);
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
        });
    }
    else {
        LOG_INFO("Nothing was selected to run, skipping.");
    }
}

void debugContinueAction(const bool skipBP) {
    LOG_DEBUG("Continuing debugging requested...");
    
    executeInBackground([skipBP]{
        // Wait until debugging state is fully ready
        {
            std::unique_lock<std::mutex> lk(debugReadyMutex);
            debugReadyCv.wait(lk, []{ return isDebugReady; });
        }
        LOG_DEBUG("Debug state confirmed ready, proceeding with continue.");

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
        runningAsContinue = true;

        // Execute in the current thread (we're already in a background thread)
        stepCode(0);
        
        // Update UI after execution
        if (!executionComplete) {
            const std::string lineNoStr = addressLineNoMap[std::to_string(icicle_get_pc(icicle))];
            if (!lineNoStr.empty()) {
                int lineNo = std::atoi(lineNoStr.c_str());
                safeHighlightLine(lineNo - 1);
            }
        } else {
            safeHighlightLine(lastInstructionLineNo - 1);
        }

        skipBreakpoints = false;
        runningAsContinue = false;
        eraseTempBP = false;
        LOG_DEBUG("Continue action finished.");
    });
    
}

void runActions(){
    processUIUpdates();
    
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
            debugContinueAction(false);
            debugContinue = false;
        }
        if (debugStepOver){
            if (isCodeRunning){
                debugStepOver = false;
                return;
            }
            stepOverAction();
            debugStepOver = false;
        }
        else if (debugStepIn){
            if (isCodeRunning){
                debugStepIn = false;
                return;
            }
            stepInAction();
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
        LOG_DEBUG("Run until line is " << runUntilLine);
        if (!debugModeEnabled){
            startDebugging();
        }
        
        executeInBackground([]{
            {
                std::unique_lock<std::mutex> lk(debugReadyMutex);
                debugReadyCv.wait(lk, []{ return isDebugReady; });
            }

            skipEndStep = true;
            addBreakpointToLine(runUntilLine, true);
            printBreakpoints();
            stepCode(0);
            skipEndStep = false;

            if (!executionComplete) {
                const std::string lineNoStr = addressLineNoMap[std::to_string(icicle_get_pc(icicle))];
                if (!lineNoStr.empty()) {
                    const int lineNo = std::atoi(lineNoStr.c_str());
                    safeHighlightLine(lineNo - 1);
                }
            }
            
            // Remove temporary breakpoint
            icicle_remove_breakpoint(icicle, lineNoToAddress(runUntilLine));
        });
        
        runUntilHere = false;
    }
    if (debugRun){
        if (isCodeRunning){
            debugRun = false;
            return;
        }
        executeInBackground([]{
            skipBreakpoints = true;
            // Initialize debugging environment first
            if (!debugModeEnabled) {
                LOG_INFO("Initializing debug environment for run...");
                // We need to ensure debugging is set up without blocking for input
                if (!isDebugReady) {
                    {
                        std::lock_guard<std::mutex> lk(debugReadyMutex);
                        isDebugReady = false;
                    }
                    if (!fileRunTask(false)) {
                        LOG_ERROR("Failed to initialize debugging environment");
                        skipBreakpoints = false;
                        return;
                    }
                    debugModeEnabled = true;
                }
            }
            
            if ((resetState()) && (fileRunTask(true))){
                // Execution was successful
                // Update UI after run
                if (executionComplete) {
                    safeHighlightLine(lastInstructionLineNo - 1);
                }
            }
            else {
                LOG_ERROR("Failed to run code");
            }
            skipBreakpoints = false;
        });

        debugRun = false;
    }

    if (saveFile){
        LOG_INFO("File save requested!");
        fileSaveTask(selectedFile);
        saveFile = false;
    }
    if (openFile){
        LOG_INFO("File open dialog requested!");
        executeInBackground([](){
            resetState();
            fileOpenTask(openFileDialog());
        });
        openFile = false;
    }
    if (saveFileAs){
        LOG_INFO("File save as requested!");
        fileSaveAsTask(saveAsFileDialog());
        saveFileAs = false;
    }
    if (fileLoadContext){
        LOG_INFO("Loading context from file requested!");
        executeInBackground([](){
            fileLoadUCContextFromJson(openFileDialog());
            const uint64_t ip = icicle_get_pc(icicle);
            const std::string str = addressLineNoMap[std::to_string(ip)];
            if (!str.empty()) {
                const int lineNumber = std::atoi(str.c_str());
                safeHighlightLine(lineNumber - 1);
            }
        });
        fileLoadContext = false;
    }

    if (toggleBreakpoint){
        debugToggleBreakpoint();
        toggleBreakpoint = false;
    }

    if (changeEmulationSettingsOpt){
        changeEmulationSettings();
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

    if (memoryMapsUI)
    {
        // LOG_INFO("Unimplemented");
        memoryMapWindow();
    }
}
