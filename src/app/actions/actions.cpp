#include <thread>
#include <condition_variable>
#include <functional>
#include "actions.hpp"

#include "imgui_impl_opengl3_loader.h"
#include "../integration/interpreter/interpreter.hpp"

std::mutex uiUpdateMutex;
bool pendingUIUpdate = false;
int pendingHighlightLine = -1;
int times = 1;

void openBrowser(const std::string& url) {
#ifdef _WIN32
    std::string command = "start " + url;
#elif __APPLE__
    std::string command = "open " + url;
#else
    std::string command = "xdg-open " + url;
#endif
    system(command.c_str());
}

std::string currentVersion{};
std::string getLatestVersion()
{
    httplib::SSLClient cli("raw.githubusercontent.com");
    if (auto res = cli.Get("/ZathuraDbg/ZathuraDbg/refs/heads/master/VERSION")) {
        std::erase(res->body, '\n');
        return res->body;
    } else {
        return "";
    }
}

void updateWindow()
{
    if (currentVersion.empty())
    {
        currentVersion = getLatestVersion();
        if (currentVersion.empty())
        {
            if (tinyfd_messageBox("Error", "Failed to check for updates! Your internet may not be working", "ok", "error", 0))
            {
                return;
            }
        }
    }

    const bool latest = (currentVersion == VERSION) ? true : false;
    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[SatoshiBold24]);
    ImGui::PushStyleVar(ImGuiStyleVar_PopupBorderSize, 5.0f);
    const auto windowTextPos = ImGui::CalcTextSize("Update Zathura");

    // {width, height}
    constexpr auto popupSize = ImVec2(270, 150);
    ImGui::SetNextWindowSize(popupSize);
    ImGui::PushStyleColor(ImGuiCol_PopupBg, ImColor(0x1e, 0x20, 0x2f).Value);
    ImVec2 windowSize = ImGui::GetIO().DisplaySize;
    ImVec2 popupPos = ImVec2((windowSize.x - popupSize.x) * 0.5f, (windowSize.y - popupSize.y) * 0.5f);

    ImGui::OpenPopup("Update");
    if (ImGui::BeginPopup("Update"))
    {
        const ImVec2 windowSize = ImGui::GetWindowSize();
        ImGui::SetCursorPosX((windowSize.x - windowTextPos.x) * 0.7f);
        ImGui::Text("%s", "Update");
        ImGui::SeparatorEx(ImGuiSeparatorFlags_Horizontal, 3);
        ImGui::Dummy(ImVec2(0.0f, 10.0f));
        ImGui::NewLine();
        ImGui::SameLine(0, 10);

        if (latest)
        {
            ImGui::TextWrapped("Fantastic! You're on the latest version: %s", VERSION.c_str());
            ImGui::Dummy({40, 10});
            ImGui::Dummy({40, 0});
            ImGui::SameLine(0, 150);
        }
        else
        {
            ImGui::Text("Hooray! An update is available");
            ImGui::SameLine(0, 4);
            // ImGui::SetNextItemWidth(150);
            ImGui::Dummy(ImVec2(0.0f, 10.0f));
            ImGui::Dummy({0, 4});
            ImGui::SameLine(0, 8);
            ImGui::Text("Available version: %s", currentVersion.c_str());
            ImGui::Dummy({0, 4});
            ImGui::SameLine(0, 8);
            ImGui::Dummy(ImVec2(0.0f, 6.0f));
            ImGui::Dummy(ImVec2(0.0f, 0.0f));
            ImGui::SameLine(8, 8);
            if (ImGui::Button("Download"))
            {
                openBrowser("https://github.com/ZathuraDbg/ZathuraDbg/releases/latest");
            }

        ImGui::SameLine(0, 100);
        }


        if (ImGui::Button("Close"))
        {
            LOG_INFO("Closing...");
            showUpdateWindow = false;
        }
        ImGui::EndPopup();
    }

    ImGui::PopStyleColor();
    ImGui::PopStyleVar();
    ImGui::PopFont();
}

void stepBack()
{
    if (vmSnapshots.empty())
    {
        LOG_INFO("No more snapshots to step back to.");
        return;
    }

    VmSnapshot* stateToRestore = vmSnapshots.top();
    vmSnapshots.pop();

    icicle_vm_restore(icicle, stateToRestore);

    safeHighlightLine(addressLineNoMap[icicle_get_pc(icicle)] - 1);
    updateRegs(false);
    icicle_vm_snapshot_free(stateToRestore);

    if (snapshot) {
        icicle_vm_snapshot_free(snapshot);
        snapshot = nullptr;
    }

    snapshot = icicle_vm_snapshot(icicle);
    LOG_DEBUG("Stepped back successfully. Snapshots remaining: " << vmSnapshots.size());
}

void executeInBackground(const std::function<void()>& func) {
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
    
}

void restartDebugging(){
    LOG_INFO("Restarting debugging...");
    
    executeInBackground([]{
        resetState();
        fileRunTask(false);
        LOG_INFO("Debugging restarted successfully.");
    });
    
}


void stepOverAction(){
    LOG_INFO("Step over requested...");

    executeInBackground([]{
        // Wait until debugging state is fully ready
        {
            std::unique_lock<std::mutex> lk(debugReadyMutex);
            debugReadyCv.wait(lk, []{ return isDebugReady; });
        }
        LOG_DEBUG("Debug state confirmed ready, proceeding with step over.");

        // It may cause issues if the actual line is 0 and not undefined. (Need to start from 1)
        const uint64_t lineNo = addressLineNoMap[icicle_get_pc(icicle)];

        if (lineNo){
            
            breakpointMutex.lock();
            auto bpLineNoAddr = lineNoToAddress(lineNo + 1);
            icicle_add_breakpoint(icicle, bpLineNoAddr);
            breakpointLines.push_back(lineNo + 1); // Track the temporary breakpoint
            breakpointMutex.unlock();

            // Run until the next line (or breakpoint)
            executeCode(icicle, 0); // Use executeCode which handles breakpoints

            // Update UI with new position
            if (!executionComplete) {
                const uint64_t newLineNo = addressLineNoMap[icicle_get_pc(icicle)];
                if (newLineNo)
                    safeHighlightLine(newLineNo - 1);
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
    
}

void stepInAction(){
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
                const uint64_t newLineNo = addressLineNoMap[icicle_get_pc(icicle)];
                if (newLineNo)
                    safeHighlightLine(newLineNo - 1);
        }
        
        stepIn = false;
        pauseNext = false; // Reset flag
        LOG_INFO("Stepping in done.");
    });
    
}

bool debugPaused = false;
void debugPauseAction(){
    LOG_INFO("Pause action requested!");
    
    executeInBackground([]{
        auto instructionPointer = getRegisterValue(archIPStr);
        const uint64_t lineNumber = addressLineNoMap[instructionPointer.eightByteVal];

        safeHighlightLine(lineNumber - 1);
        debugPaused = true;
        // Free existing snapshot before creating a new one
        if (snapshot) {
            icicle_vm_snapshot_free(snapshot);
            snapshot = nullptr;
        }
        snapshot = saveICSnapshot(icicle); // Assign the saved snapshot
        LOG_INFO("Code paused successfully!");
    });
}

void debugStopAction(){
    debugModeEnabled = false;
    resetState();
    LOG_INFO("Debugging stopped successfully.");
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
    const auto breakpointIter = (std::ranges::find(breakpointLines, lineNum + 1));

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
                const uint64_t newLineNo = addressLineNoMap[icicle_get_pc(icicle)];
                if (newLineNo)
                    safeHighlightLine(newLineNo - 1);
        }
        else
            safeHighlightLine(lastInstructionLineNo - 1);

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
            stepCode(0);
            skipEndStep = false;

            if (!executionComplete) {
                const uint64_t newLineNo = addressLineNoMap[icicle_get_pc(icicle)];
                if (newLineNo)
                    safeHighlightLine(newLineNo - 1);
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
            resetState(false);
            fileOpenTask(openFileDialog());
        });
        openFile = false;
    }
    if (createFile)
    {
        LOG_INFO("File create requested!");
        const auto s = saveAsFileDialog();
        if (!s.empty())
        {
            fopen(s.c_str(), "w");
            fileOpenTask(s);
            // resetState(false);
            // selectedFile = s;
            // getBytes(selectedFile);
            // initInsSizeInfoMap();
        }
        createFile = false;
    }
    if (saveFileAs){
        LOG_INFO("File save as requested!");
        fileSaveAsTask(saveAsFileDialog());
        saveFileAs = false;
    }

    if (fileSerializeState){
        serializeState();
        fileSerializeState = false;
    }

    if (fileDeserializeState)
    {
        deserializeState();
        fileDeserializeState = false;
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
        memoryMapWindow();
    }

    if (debugStepBack)
    {
        stepBack();
        debugStepBack = false;
    }

    if (showUpdateWindow)
    {
        updateWindow();
    }

}
