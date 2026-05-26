#include <thread>
#include <condition_variable>
#include <functional>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif
#include "actions.hpp"

#include "imgui_impl_opengl3_loader.h"
#include "../integration/interpreter/interpreter.hpp"

std::mutex uiUpdateMutex;
bool pendingUIUpdate = false;
int pendingHighlightLine = -1;
bool pendingRemoteUiSync = false;
bool pendingRemoteRefreshTarget = false;
bool pendingRemoteResetCodeMemoryBase = false;
int times = 1;
std::optional<uint64_t> remoteDisassemblyBaseAddress{};

static void syncRemoteUiState(bool refreshTarget, bool resetCodeMemoryBase);

void openBrowser(const std::string& url) {
#ifdef _WIN32
    ShellExecuteA(nullptr, "open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
#elif __APPLE__
    pid_t pid = fork();
    if (pid == 0) {
        execlp("open", "open", url.c_str(), nullptr);
        _exit(1);
    }
#else
    pid_t pid = fork();
    if (pid == 0) {
        execlp("xdg-open", "xdg-open", url.c_str(), nullptr);
        _exit(1);
    }
#endif
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

void requestRemoteUiSync(const bool refreshTarget, const bool resetCodeMemoryBase) {
    std::lock_guard<std::mutex> lock(uiUpdateMutex);
    pendingRemoteUiSync = true;
    pendingRemoteRefreshTarget = pendingRemoteRefreshTarget || refreshTarget;
    pendingRemoteResetCodeMemoryBase = pendingRemoteResetCodeMemoryBase || resetCodeMemoryBase;
}

void processUIUpdates() {
    bool applyHighlight = false;
    int highlightLine = -1;
    bool applyRemoteSync = false;
    bool refreshTarget = false;
    bool resetCodeMemoryBase = false;

    {
        std::lock_guard<std::mutex> lock(uiUpdateMutex);
        if (pendingUIUpdate) {
            applyHighlight = true;
            highlightLine = pendingHighlightLine;
            pendingUIUpdate = false;
        }

        if (pendingRemoteUiSync) {
            applyRemoteSync = true;
            refreshTarget = pendingRemoteRefreshTarget;
            resetCodeMemoryBase = pendingRemoteResetCodeMemoryBase;
            pendingRemoteUiSync = false;
            pendingRemoteRefreshTarget = false;
            pendingRemoteResetCodeMemoryBase = false;
        }
    }

    if (applyRemoteSync) {
        syncRemoteUiState(refreshTarget, resetCodeMemoryBase);
    }

    if (applyHighlight) {
        editor->HighlightDebugCurrentLine(highlightLine);
    }
}

static void rebuildRemoteBreakpointHighlights() {
    breakpointLines.clear();
    editor->HighlightBreakpoints(-1, true);

    for (const auto address : breakpointAddresses) {
        const auto it = addressLineNoMap.find(address);
        if (it == addressLineNoMap.end() || it->second == 0) {
            continue;
        }

        breakpointLines.push_back(it->second);
        editor->HighlightBreakpoints(static_cast<int>(it->second - 1));
    }
}

static void syncRemoteCodeView() {
    const auto currentPc = remote_gdb::remoteProgramCounter();
    if (!currentPc.has_value()) {
        consoleWriteThreadSafe("remote >> failed to read the current pc for disassembly\n");
        addressLineNoMap.clear();
        breakpointLines.clear();
        editor->HighlightBreakpoints(-1, true);
        showRemoteDisassemblyInEditor("; remote disassembly unavailable: current pc could not be read", -1);
        safeHighlightLine(-1);
        return;
    }

    if (!remoteDisassemblyBaseAddress.has_value() ||
        (!addressLineNoMap.empty() && !addressLineNoMap.contains(*currentPc))) {
        remoteDisassemblyBaseAddress = *currentPc;
    }

    auto view = remote_gdb::remoteBuildDisassemblyView(64, remoteDisassemblyBaseAddress);
    if ((!view.has_value() || view->currentLine == 0) && remoteDisassemblyBaseAddress != *currentPc) {
        remoteDisassemblyBaseAddress = *currentPc;
        view = remote_gdb::remoteBuildDisassemblyView(64, remoteDisassemblyBaseAddress);
    }

    if (!view.has_value()) {
        consoleWriteThreadSafe("remote >> failed to build the disassembly view\n");
        addressLineNoMap.clear();
        breakpointLines.clear();
        editor->HighlightBreakpoints(-1, true);
        showRemoteDisassemblyInEditor("; remote disassembly unavailable for the current target state", -1);
        safeHighlightLine(-1);
        return;
    }

    addressLineNoMap = view->addressLineMap;
    labelLineNoMapInternal = view->labelMap;
    labels.clear();
    for (const auto& [name, line] : view->labelMap) {
        labels.push_back(name);
    }
    emptyLineNumbers.clear();
    lastInstructionLineNo = view->addressLineMap.size();
    ENTRY_POINT_ADDRESS = view->startAddress;
    remoteDisassemblyBaseAddress = view->startAddress;

    showRemoteDisassemblyInEditor(view->text, static_cast<int>(view->currentLine > 0 ? view->currentLine - 1 : 0),
                                  view->lineOffsetLabels, view->lineAddressLabels);
    rebuildRemoteBreakpointHighlights();

    if (view->currentLine > 0) {
        safeHighlightLine(static_cast<int>(view->currentLine - 1));
    } else {
        safeHighlightLine(-1);
    }
}

static void initRemoteAddresses() {
    if (const auto pc = remote_gdb::remoteProgramCounter(); pc.has_value()) {
        MEMORY_EDITOR_BASE = *pc & ~static_cast<uint64_t>(0xfff);
    }
    if (const auto sp = remote_gdb::remoteStackPointer(); sp.has_value()) {
        STACK_ADDRESS = *sp;
    }
}

static void syncRemoteUiState(const bool refreshTarget, const bool resetCodeMemoryBase) {
    if (refreshTarget && !remote_gdb::remoteRefreshState()) {
        consoleWriteThreadSafe("remote >> failed to refresh target state\n");
        return;
    }

    codeHasRun = true;
    syncRemoteCodeView();
    updateRegs();
    updateStack = true;

    if (const auto pc = remote_gdb::remoteProgramCounter(); pc.has_value()) {
        if (resetCodeMemoryBase || remoteMemoryViewFollowsPc) {
            MEMORY_EDITOR_BASE = *pc & ~static_cast<uint64_t>(0xfff);
        }
    }

    if (const auto sp = remote_gdb::remoteStackPointer(); sp.has_value()) {
        STACK_ADDRESS = *sp;
    }
}

void startOrRefreshRemoteDebugSession() {
    executeInBackground([]{
        if (!remote_gdb::useRemoteDebugging()) {
            consoleWriteThreadSafe("remote >> remote gdb mode is not enabled\n");
            return;
        }

        if (!remote_gdb::remoteDebugConnected()) {
            {
                std::lock_guard<std::mutex> lk(debugReadyMutex);
                isDebugReady = false;
            }

            if (!remote_gdb::connectRemoteDebugSession()) {
                consoleWriteThreadSafe("remote >> failed to connect\n");
                {
                    std::lock_guard<std::mutex> lk(debugReadyMutex);
                    isDebugReady = true;
                }
                debugReadyCv.notify_all();
                return;
            }

            initRemoteAddresses();

            {
                std::lock_guard<std::mutex> lk(debugReadyMutex);
                isDebugReady = true;
            }
            debugReadyCv.notify_all();
            debugModeEnabled = true;
            remoteMemoryViewFollowsPc = true;
            remoteDisassemblyBaseAddress.reset();
            requestRemoteUiSync(false, true);
            consoleWriteThreadSafe("remote >> connected\n");
            return;
        }

        debugModeEnabled = true;
        requestRemoteUiSync(false, true);
        consoleWriteThreadSafe("remote >> ui refresh requested\n");
    });
}

bool debugAddBreakpointAddress(const uint64_t address) {
    if (!address) {
        return false;
    }

    if (std::ranges::find(breakpointAddresses, address) != breakpointAddresses.end()) {
        return false;
    }

    if (remote_gdb::useRemoteDebugging()) {
        if (!remote_gdb::remoteAddBreakpoint(address)) {
            return false;
        }
    } else if (!addBreakpoint(address, false)) {
        return false;
    }

    breakpointAddresses.push_back(address);
    const auto it = addressLineNoMap.find(address);
    if (it != addressLineNoMap.end() && it->second > 0) {
        breakpointLines.push_back(it->second);
        editor->HighlightBreakpoints(static_cast<int>(it->second - 1));
    }

    return true;
}

bool debugRemoveBreakpointAddress(const uint64_t address) {
    const auto addressIt = std::ranges::find(breakpointAddresses, address);
    if (addressIt == breakpointAddresses.end()) {
        return false;
    }

    if (remote_gdb::useRemoteDebugging()) {
        if (!remote_gdb::remoteRemoveBreakpoint(address)) {
            return false;
        }
    } else if (!removeBreakpoint(address)) {
        return false;
    }

    breakpointAddresses.erase(addressIt);
    const auto lineIt = addressLineNoMap.find(address);
    if (lineIt != addressLineNoMap.end() && lineIt->second > 0) {
        const auto bpLineIt = std::ranges::find(breakpointLines, lineIt->second);
        if (bpLineIt != breakpointLines.end()) {
            breakpointLines.erase(bpLineIt);
            editor->RemoveHighlight(static_cast<int>(lineIt->second - 1));
        }
    }

    return true;
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
        if (remote_gdb::useRemoteDebugging()) {
            if (!remote_gdb::connectRemoteDebugSession()) {
                LOG_ERROR("Unable to start remote debugging.");
                {
                    std::lock_guard<std::mutex> lk(debugReadyMutex);
                    isDebugReady = true;
                }
                debugReadyCv.notify_all();
                return;
            }

            initRemoteAddresses();

            {
                std::lock_guard<std::mutex> lk(debugReadyMutex);
                isDebugReady = true;
            }
            debugReadyCv.notify_all();
            debugModeEnabled = true;
            remoteMemoryViewFollowsPc = true;
            remoteDisassemblyBaseAddress.reset();
            requestRemoteUiSync(false, true);
            LOG_INFO("Remote debugging connected successfully.");
            return;
        }

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
        if (remote_gdb::useRemoteDebugging()) {
            if (remote_gdb::remoteRestartSession()) {
                remoteMemoryViewFollowsPc = true;
                remoteDisassemblyBaseAddress.reset();
                requestRemoteUiSync(false, true);
            } else {
                consoleWriteThreadSafe("remote >> restart failed\n");
            }
            return;
        }
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

        if (remote_gdb::useRemoteDebugging()) {
            if (remote_gdb::remoteStepOver()) {
                requestRemoteUiSync(false);
            } else {
                consoleWriteThreadSafe("remote >> step-over failed\n");
            }
            return;
        }

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

        if (remote_gdb::useRemoteDebugging()) {
            if (remote_gdb::remoteStep()) {
                requestRemoteUiSync(false);
            } else {
                consoleWriteThreadSafe("remote >> step failed\n");
            }
            return;
        }

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
        if (remote_gdb::useRemoteDebugging()) {
            if (remote_gdb::remotePause()) {
                requestRemoteUiSync(false);
            } else {
                consoleWriteThreadSafe("remote >> interrupt failed\n");
            }
            return;
        }
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
    if (remote_gdb::useRemoteDebugging()) {
        remote_gdb::disconnectRemoteDebugSession();
    }
    debugModeEnabled = false;
    resetState();
    LOG_INFO("Debugging stopped successfully.");
}

void debugToggleBreakpoint(){
    int line, _;
    editor->GetCursorPosition(line, _);
    if (!debugRemoveBreakpoint(line)) {
        debugAddBreakpoint(line);
    }
}

bool debugAddBreakpoint(const int lineNum){
    LOG_DEBUG("Adding breakpoint on the line " << lineNum);

    if (remote_gdb::useRemoteDebugging()) {
        if (std::ranges::find(breakpointLines, lineNum + 1) != breakpointLines.end()) {
            return false;
        }
        const auto address = lineNoToAddress(lineNum + 1);
        if (!address) {
            consoleWriteThreadSafe("remote >> cannot resolve line to address for breakpoint\n");
            return false;
        }
        return debugAddBreakpointAddress(address);
    }

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
        breakpointAddresses.push_back(lineNoToAddress(lineNum + 1));
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
        if (remote_gdb::useRemoteDebugging()) {
            const auto address = lineNoToAddress(lineNum + 1);
            if (!address) {
                return false;
            }
            return debugRemoveBreakpointAddress(address);
        }
        if (!removeBreakpointFromLineNo(lineNum + 1)) {
            return false;
        }
        const auto address = lineNoToAddress(lineNum + 1);
        const auto addressIter = std::ranges::find(breakpointAddresses, address);
        if (addressIter != breakpointAddresses.end()) {
            breakpointAddresses.erase(addressIter);
        }
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

        if (remote_gdb::useRemoteDebugging()) {
            if (remote_gdb::remoteContinue()) {
                requestRemoteUiSync(false);
            } else {
                consoleWriteThreadSafe("remote >> continue failed\n");
            }
            return;
        }

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

        if (remote_gdb::useRemoteDebugging()) {
            const auto targetAddress = lineNoToAddress(runUntilLine + 1);
            if (!targetAddress) {
                consoleWriteThreadSafe("remote >> cannot resolve the selected disassembly line to an address\n");
                runUntilHere = false;
                return;
            }

            executeInBackground([targetAddress]{
                {
                    std::unique_lock<std::mutex> lk(debugReadyMutex);
                    debugReadyCv.wait(lk, []{ return isDebugReady; });
                }

                const bool alreadyTracked =
                    std::ranges::find(breakpointAddresses, targetAddress) != breakpointAddresses.end();
                bool temporaryBreakpoint = false;

                if (!alreadyTracked) {
                    if (!remote_gdb::remoteAddBreakpoint(targetAddress)) {
                        consoleWriteThreadSafe("remote >> failed to add a temporary breakpoint for run-until-here\n");
                        return;
                    }
                    temporaryBreakpoint = true;
                }

                if (remote_gdb::remoteContinue()) {
                    requestRemoteUiSync(false);
                } else {
                    consoleWriteThreadSafe("remote >> run-until-here continue failed\n");
                }

                if (temporaryBreakpoint && !remote_gdb::remoteRemoveBreakpoint(targetAddress)) {
                    consoleWriteThreadSafe("remote >> warning: failed to remove the temporary run-until-here breakpoint\n");
                }
            });

            runUntilHere = false;
        } else {
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
    }
    if (debugRun){
        if (isCodeRunning){
            debugRun = false;
            return;
        }
        executeInBackground([]{
            if (remote_gdb::useRemoteDebugging()) {
                if (!debugModeEnabled) {
                    {
                        std::lock_guard<std::mutex> lk(debugReadyMutex);
                        isDebugReady = false;
                    }
                    if (!remote_gdb::connectRemoteDebugSession()) {
                        consoleWriteThreadSafe("remote >> failed to connect for run\n");
                        return;
                    }
                    {
                        std::lock_guard<std::mutex> lk(debugReadyMutex);
                        isDebugReady = true;
                    }
                    debugReadyCv.notify_all();
                    debugModeEnabled = true;
                    remoteMemoryViewFollowsPc = true;
                    remoteDisassemblyBaseAddress.reset();
                }

                if (remote_gdb::remoteContinue()) {
                    requestRemoteUiSync(false, true);
                } else {
                    consoleWriteThreadSafe("remote >> run/continue failed\n");
                }
                return;
            }

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
        if (editorShowingRemoteDisassembly()) {
            consoleWriteThreadSafe("remote >> run selected code is unavailable while the code pane is showing remote disassembly\n");
        } else {
            debugRunSelectionAction();
        }
        runSelectedCode = false;
    }

    if (goToDefinition){
        if (editorShowingRemoteDisassembly()) {
            consoleWriteThreadSafe("remote >> go to definition is unavailable in the remote disassembly view\n");
        } else {
            LOG_INFO("Going to label's definiton...");
            editor->SelectLabelDefinition(false);
        }
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
