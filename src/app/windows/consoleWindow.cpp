#include "windows.hpp"
#include <functional>
#include <unordered_map>
#include <mutex>

// ============================================================
// Console state
// ============================================================
std::string consoleOutput;
std::mutex  consoleOutputMutex;

static std::vector<std::string> commandHistory;
static int              historyPos   = -1;
static bool             firstRender  = true;
static bool             autoScroll   = true;

static char displayBuffer[131072]; // 128KB
static bool bufferDirty = true;

static std::string formatHexByte(uint8_t byte) {
    constexpr char digits[] = "0123456789abcdef";
    std::string out(2, '0');
    out[0] = digits[(byte >> 4) & 0xf];
    out[1] = digits[byte & 0xf];
    return out;
}

// ============================================================
// Helpers
// ============================================================
static void consoleWrite(const std::string& text) {
    std::lock_guard<std::mutex> lock(consoleOutputMutex);
    consoleOutput += text + "\n";
    bufferDirty = true;
}

void consoleWriteThreadSafe(const std::string& text) {
    std::lock_guard<std::mutex> lock(consoleOutputMutex);
    consoleOutput += text;
    bufferDirty = true;
}

// ============================================================
// Parsing / utility helpers
// ============================================================

std::string convToDec(const std::string& str) {
    std::string outStr;
    bool foundHexStr = false;

    for (size_t i = 0; i < str.length(); i++) {
        if (str[i] == '0' && (str[i + 1] == 'x' || str[i + 1] == 'X')) {
            i++;
            foundHexStr = true;
            continue;
        }

        if (foundHexStr) {
            char* endptr  = nullptr;
            const auto convVal = strtoul(str.substr(i).c_str(), &endptr, 16);
            const size_t diff  = endptr - str.substr(i).c_str() - 1;
            outStr += std::to_string(convVal);
            i += diff;
            foundHexStr = false;
            continue;
        }

        outStr += str[i];
    }
    return outStr;
}

uint64_t doubleToUint64(double d) {
    const double rounded = std::round(d);
    if (rounded < 0 || rounded > static_cast<double>(std::numeric_limits<uint64_t>::max())) {
        return 0;
    }
    return static_cast<uint64_t>(rounded);
}

std::string parseVals(std::string val) {
    std::string result;
    std::string regName;
    std::vector<std::string> regNames = {};
    bool foundReg      = false;
    bool foundValidReg = false;
    const auto len     = val.length();

    size_t i = 0;
    val      = toUpperCase(val);
    val += " ";
    for (auto& c : val) {
        if (isRegisterValid(regName) && (!foundValidReg)) {
            foundValidReg = true;
        }

        if (foundValidReg) {
            if (c == ' ' || c == '$' || c == '+' || c == '-' || c == '/' || c == '*' || (i == len)) {
                foundReg      = false;
                foundValidReg = false;
                regNames.push_back(regName);
                std::string registerValue;
                if (!codeHasRun) {
                    registerValue = tempRegisterValueMap[regName];
                } else {
                    if (regInfoMap[regName] <= 64) {
                        registerValue = std::to_string(getRegisterValue(regName).eightByteVal);
                    } else if (regInfoMap[regName] == 128) {
                        registerValue = std::to_string(getRegisterValue(regName).floatVal);
                    }
                }

                if (registerValue.starts_with("0x")) {
                    result += std::to_string(hexStrToInt(registerValue));
                } else {
                    result += registerValue;
                }

                if (result.empty()) {
                    result += "0";
                }

                if (c != ' ') {
                    result += c;
                }

                regName.clear();
                i++;
                continue;
            } else {
                regName.clear();
            }
        }

        if (c == '$') {
            foundReg = true;
            i++;
            continue;
        }

        if (foundReg) {
            regName += c;
        }

        if (c != ' ' && (!foundReg)) {
            result += c;
        }

        i++;
    }

    return std::to_string(doubleToUint64(te_interp(convToDec(result).data(), nullptr)));
}

void splitStringExpressions(std::string stringToSplit, std::vector<std::string>& stringVec) {
    std::string token;
    stringToSplit += ' ';
    for (size_t j = 0; j < stringToSplit.length(); j++) {
        const char c = stringToSplit[j];

        if (c == '+' || c == '-' || c == '*' || c == '/') {
            if (!token.empty()) {
                stringVec.emplace_back(std::move(token));
                token.clear();
            }
            stringVec.emplace_back(1, c);
            continue;
        }

        if (c == ' ') {
            if (!token.empty()) {
                stringVec.emplace_back(std::move(token));
                token.clear();
            }
            continue;
        }

        token += c;
    }
}

std::string getAddressFromLineNo(int lineNo) {
    for (auto& [fst, snd] : addressLineNoMap) {
        if (snd == lineNo) {
            std::stringstream result;
            result << "0x" << std::setfill('0') << std::hex << fst;
            return " at " + result.str();
        }
    }
    return "";
}

static int parseBreakpointArgs(std::vector<std::string>& arguments,
                               const std::string& argument,
                               std::string& outStr) {
    const std::regex labelPattern("^[a-zA-Z_][a-zA-Z0-9_]*$");
    int lineNo = 0;
    if (arguments[0].starts_with("0x") || arguments[0].starts_with('$')) {
        lineNo = addressLineNoMap[atoi(parseVals(argument).c_str())];
        outStr += "address " + std::to_string(lineNo);
    } else if (std::regex_match(arguments[0], labelPattern)) {
        if (labelLineNoMapInternal.count(arguments[0]) != 0) {
            lineNo = labelLineNoMapInternal[arguments[0]] + 1;
        }
        outStr += "label " + arguments[0] + " at line no. " + std::to_string(lineNo);
    } else if (std::all_of(arguments[0].begin(), arguments[0].end(), ::isdigit)) {
        lineNo = std::atoi(parseVals(argument).c_str());
        outStr += "line number " + std::to_string(lineNo) + getAddressFromLineNo(lineNo);
    }
    return lineNo;
}

// ============================================================
// Command system
// ============================================================
using CommandHandler = std::function<void(const std::vector<std::string>&)>;

struct CommandInfo {
    std::string    description;
    std::string    helpText;
    CommandHandler handler;
};

static std::unordered_map<std::string, CommandInfo> commands;

static std::string joinArguments(const std::vector<std::string>& arguments, size_t startIndex = 0) {
    std::string joined;
    for (size_t i = startIndex; i < arguments.size(); ++i) {
        if (!joined.empty()) {
            joined += ' ';
        }
        joined += arguments[i];
    }
    return joined;
}

// --- Individual command handlers ---

static void cmdHelp(const std::vector<std::string>&);

static void cmdRun(const std::vector<std::string>&) {
    consoleWrite("Running code...");
    debugRun = true;
}

static void cmdStart(const std::vector<std::string>&) {
    consoleWrite("Starting debug mode...");
    enableDebugMode = true;
}

static void cmdRestart(const std::vector<std::string>&) {
    consoleWrite("Restarting debugging...");
    debugRestart = true;
}

static void cmdPause(const std::vector<std::string>&) {
    consoleWrite("Pausing execution...");
    debugPause = true;
}

static void cmdContinue(const std::vector<std::string>&) {
    consoleWrite("Continuing execution...");
    debugContinue = true;
}

static void cmdStop(const std::vector<std::string>&) {
    consoleWrite("Stopping debug mode...");
    debugStop = true;
}

static void cmdNext(const std::vector<std::string>&) {
    debugStepOver = true;
}

static void cmdStep(const std::vector<std::string>&) {
    debugStepIn = true;
}

static void cmdTarget(const std::vector<std::string>& arguments) {
    if (arguments.empty() || arguments[0] == "status") {
        consoleWrite("Target mode: " + std::string(remote_gdb::useRemoteDebugging() ? "remote" : "local"));
        consoleWrite("Endpoint: " + remote_gdb::remoteConnectionLabel());
        consoleWrite("Connected: " + std::string(remote_gdb::remoteDebugConnected() ? "yes" : "no"));
        const auto stopReason = remote_gdb::remoteLastStopReason();
        if (!stopReason.empty()) {
            consoleWrite("Last stop: " + stopReason);
        }
        return;
    }

    const auto subcommand = toLowerCase(arguments[0]);
    if (subcommand == "connect") {
        if (arguments.size() > 1) {
            remote_gdb::remoteConnectionConfig.host = arguments[1];
        }
        if (arguments.size() > 2) {
            const auto port = std::strtol(arguments[2].c_str(), nullptr, 10);
            if (port > 0 && port < 65536) {
                remote_gdb::remoteConnectionConfig.port = static_cast<uint16_t>(port);
            }
        }
        remote_gdb::debugTargetMode = remote_gdb::DebugTargetMode::RemoteGdb;
        startOrRefreshRemoteDebugSession();
        consoleWrite("Remote connection requested.");
        return;
    }

    if (subcommand == "disconnect") {
        debugStop = true;
        consoleWrite("Remote disconnect requested.");
        return;
    }

    if (subcommand == "mode" && arguments.size() > 1) {
        const auto value = toLowerCase(arguments[1]);
        if (value == "local") {
            remote_gdb::debugTargetMode = remote_gdb::DebugTargetMode::Emulation;
            consoleWrite("Switched target mode to local emulation.");
            return;
        }
        if (value == "remote") {
            remote_gdb::debugTargetMode = remote_gdb::DebugTargetMode::RemoteGdb;
            consoleWrite("Switched target mode to remote gdb.");
            return;
        }
    }

    if (subcommand == "host" && arguments.size() > 1) {
        remote_gdb::remoteConnectionConfig.host = arguments[1];
        consoleWrite("Remote host set to " + remote_gdb::remoteConnectionConfig.host);
        return;
    }

    if (subcommand == "port" && arguments.size() > 1) {
        const auto port = std::strtol(arguments[1].c_str(), nullptr, 10);
        if (port > 0 && port < 65536) {
            remote_gdb::remoteConnectionConfig.port = static_cast<uint16_t>(port);
            consoleWrite("Remote port set to " + std::to_string(remote_gdb::remoteConnectionConfig.port));
            return;
        }
    }

    consoleWrite("Usage: target [status|connect [ip] [port]|disconnect|mode local|mode remote|host <ip>|port <n>]");
}

static void cmdMonitor(const std::vector<std::string>& arguments) {
    if (!remote_gdb::remoteDebugConnected()) {
        consoleWrite("Remote target is not connected.");
        return;
    }

    const auto command = joinArguments(arguments);
    if (command.empty()) {
        consoleWrite("Usage: monitor <command>");
        return;
    }

    std::string response;
    if (remote_gdb::remoteSendMonitorCommand(command, response)) {
        consoleWrite("monitor << " + response);
    } else {
        consoleWrite("monitor command failed");
    }
}

static void cmdPacket(const std::vector<std::string>& arguments) {
    if (!remote_gdb::remoteDebugConnected()) {
        consoleWrite("Remote target is not connected.");
        return;
    }

    const auto payload = joinArguments(arguments);
    if (payload.empty()) {
        consoleWrite("Usage: packet <payload>");
        return;
    }

    std::string response;
    if (remote_gdb::remoteSendRawPacket(payload, response)) {
        consoleWrite("packet << " + response);
    } else {
        consoleWrite("raw packet failed");
    }
}

static void cmdSymbolFile(const std::vector<std::string>& arguments) {
    if (arguments.empty()) {
        consoleWrite("Usage: symbol-file <path>");
        return;
    }
    const auto& path = arguments[0];
    consoleWriteThreadSafe("remote >> loading symbols from " + path + " ...");
    if (remote_gdb::remoteLoadSymbolFile(path)) {
        const auto& syms = remote_gdb::remoteLoadedSymbols();
        consoleWrite("Loaded " + std::to_string(syms.addrToName.size()) + " symbols.");
    } else {
        consoleWrite("Failed to load symbols from " + path);
    }
}

static void cmdReadMem(const std::vector<std::string>& arguments) {
    if (arguments.size() < 2) {
        consoleWrite("Usage: readmem <hex-address> <byte-count>");
        return;
    }

    const auto address = static_cast<uint64_t>(std::strtoull(arguments[0].c_str(), nullptr, 0));
    const auto size = static_cast<size_t>(std::strtoull(arguments[1].c_str(), nullptr, 0));
    if (!size) {
        consoleWrite("Byte count must be greater than zero.");
        return;
    }

    if (remote_gdb::useRemoteDebugging()) {
        const auto data = remote_gdb::remoteReadMemory(address, size);
        if (!data.has_value()) {
            consoleWrite("Remote memory read failed.");
            return;
        }
        std::string out = "0x" + arguments[0] + ": ";
        for (const auto byte : *data) {
            out += formatHexByte(byte) + " ";
        }
        consoleWrite(out);
        return;
    }

    size_t outSize = 0;
    unsigned char* data = icicle_mem_read(icicle, address, size, &outSize);
    if (!data) {
        consoleWrite("Local memory read failed.");
        return;
    }
    std::string out = "0x" + arguments[0] + ": ";
    for (size_t i = 0; i < outSize; ++i) {
        out += formatHexByte(data[i]) + " ";
    }
    icicle_free_buffer(data, outSize);
    consoleWrite(out);
}

static std::pair<int, std::string> resolveBreakpointTarget(const std::vector<std::string>& arguments) {
    std::string argStr;
    for (size_t i = 0; i < arguments.size(); i++) {
        if (i > 0) argStr += " ";
        argStr += arguments[i];
    }
    std::vector<std::string> args;
    splitStringExpressions(argStr, args);
    std::string outStr;
    const int lineNo = parseBreakpointArgs(args, argStr, outStr);
    return {lineNo, outStr};
}

static std::optional<uint64_t> resolveBreakpointAddress(const std::vector<std::string>& arguments) {
    if (arguments.empty()) {
        return std::nullopt;
    }

    std::string argStr;
    for (size_t i = 0; i < arguments.size(); ++i) {
        if (i > 0) {
            argStr += " ";
        }
        argStr += arguments[i];
    }

    if (arguments[0].starts_with("0x") || arguments[0].starts_with('$')) {
        return static_cast<uint64_t>(std::strtoull(parseVals(argStr).c_str(), nullptr, 10));
    }

    return std::nullopt;
}

static void cmdBreakpoint(const std::vector<std::string>& arguments) {
    if (arguments.empty()) {
        consoleWrite("Usage: breakpoint <line|address|label>");
        return;
    }
    if (const auto address = resolveBreakpointAddress(arguments); address.has_value()) {
        if (debugAddBreakpointAddress(*address)) {
            consoleWrite("Added breakpoint at address 0x" + std::string(arguments[0].starts_with("0x") ? arguments[0].substr(2) : arguments[0]));
        } else {
            consoleWrite("Breakpoint at that address already exists or could not be added.");
        }
        return;
    }
    auto [lineNo, desc] = resolveBreakpointTarget(arguments);
    if (debugAddBreakpoint(lineNo - 1)) {
        consoleWrite("Added breakpoint at " + desc);
    } else {
        consoleWrite("Breakpoint at " + desc + " already exists!");
    }
}

static void cmdDelete(const std::vector<std::string>& arguments) {
    if (arguments.empty()) {
        consoleWrite("Usage: delete <line|address|label>");
        return;
    }
    if (const auto address = resolveBreakpointAddress(arguments); address.has_value()) {
        if (debugRemoveBreakpointAddress(*address)) {
            consoleWrite("Deleted breakpoint at address " + arguments[0]);
        } else {
            consoleWrite("No breakpoint at address " + arguments[0]);
        }
        return;
    }
    auto [lineNo, desc] = resolveBreakpointTarget(arguments);
    if (debugRemoveBreakpoint(lineNo - 1)) {
        consoleWrite("Deleted breakpoint at line " + desc);
    } else {
        consoleWrite("No breakpoint at " + desc);
    }
}

static std::string paddedColumn(const int base, const std::string& str, const int subNum) {
    int len = subNum - static_cast<int>(str.length());
    if (len < 0) len = 0;
    return std::string(base + len, ' ');
}

static void printLanes(const std::string& regName, int laneCount, int laneBits,
                       int spacing, bool useFloat) {
    int firstLaneNum = 0;
    for (int i = 0; i < laneCount; i++) {
        std::string outStr = regName + "[" + std::to_string(firstLaneNum) + ":";
        firstLaneNum = laneBits + laneBits * i;
        outStr += std::to_string(firstLaneNum - 1) + "]";
        auto val = useFloat
            ? std::to_string(getRegisterValue(regName).info.arrays.floatArray[i])
            : std::to_string(getRegisterValue(regName).info.arrays.doubleArray[i]);
        consoleWrite(outStr + paddedColumn(20, outStr, spacing) + val);
    }
}

static void cmdInfoRegisters(const std::vector<std::string>& arguments) {
    std::string header = "Register\t\tHex";

    if (arguments.size() > 1) {
        if (!isRegisterValid(toUpperCase(arguments[1]))) goto showAll;
        std::string regName = toUpperCase(arguments[1]);

        if (registerValueMap.contains(regName)) {
            consoleWrite(header);
            consoleWrite(regName + paddedColumn(12, regName, 4) + registerValueMap[regName]);
        } else if (!getRegisterValue(regName).info.is256bit && !getRegisterValue(regName).info.is128bit) {
            consoleWrite(header);
            consoleWrite(regName + paddedColumn(12, regName, 4) +
                         std::to_string(getRegisterValue(regName).eightByteVal));
        } else if (getRegisterValue(regName).info.is128bit) {
            consoleWrite(header);
            printLanes(regName, use32BitLanes ? 4 : 2, use32BitLanes ? 32 : 64, 12, use32BitLanes);
        } else {
            header = "Register\t\t\t\t\t\t Hex";
            consoleWrite(header);
            printLanes(regName, use32BitLanes ? 8 : 4, use32BitLanes ? 32 : 64, 13, use32BitLanes);
        }
        return;
    }

showAll:
    header = "Register\t\tHex";
    consoleWrite(header);
    for (const auto& [registerName, value] : registerValueMap) {
        consoleWrite(registerName + paddedColumn(12, registerName, 4) + value);
    }
}

static void cmdInfoBreakpoints() {
    if (breakpointLines.empty() && breakpointAddresses.empty()) {
        consoleWrite("No breakpoints found.");
        consoleWrite("Set a new one with the b/breakpoint command!");
        return;
    }
    consoleWrite("Num\t\tLine\t\tAddress");
    for (size_t j = 0; j < breakpointAddresses.size(); ++j) {
        const auto address = breakpointAddresses[j];
        const auto lineIt = addressLineNoMap.find(address);
        const auto lineText = (lineIt != addressLineNoMap.end() && lineIt->second > 0)
            ? std::to_string(lineIt->second)
            : "-";
        std::stringstream addressStream;
        addressStream << "0x" << std::hex << address;
        consoleWrite(std::to_string(j) + paddedColumn(10, lineText, 4) +
                     lineText + "       " + addressStream.str());
    }
}

static void cmdInfoLabels() {
    consoleWrite("Num\t Name\t\t\t\tLine\t\tAddress");
    int j = 1;
    for (auto& [name, line] : labelLineNoMapInternal) {
        std::string row = std::to_string(j);
        row += paddedColumn(7, name, 4) + name;
        row += paddedColumn(4, name, 16) + std::to_string(line);
        row += paddedColumn(4, std::to_string(line), 7) + getAddressFromLineNo(line + 1);
        consoleWrite(row);
        j++;
    }
}

static void cmdInfo(const std::vector<std::string>& arguments) {
    if (arguments.empty()) {
        consoleWrite("Usage: info <registers|breakpoints|labels>");
        consoleWrite("  registers, r  [name]  Show register values");
        consoleWrite("  breakpoints, b         List breakpoints");
        consoleWrite("  labels, l              List labels");
        return;
    }

    const auto& sub = arguments[0];
    if (sub == "r" || sub == "registers") { cmdInfoRegisters(arguments); return; }
    if (sub == "b" || sub == "breakpoints") { cmdInfoBreakpoints(); return; }
    if (sub == "l" || sub.starts_with("labels")) { cmdInfoLabels(); return; }

    consoleWrite("Unknown info subcommand: " + sub + ". Use: registers, breakpoints, labels.");
}

struct CmdDef {
    const char*    names;       // comma-separated: "primary,alias1,alias2"
    const char*    description;
    CommandHandler handler;
};

static const CmdDef commandDefs[] = {
    {"help,h",        "Show this help message",      cmdHelp},
    {"run,r",         "Run the assembly code",       cmdRun},
    {"start",         "Start debug mode",            cmdStart},
    {"restart,re",    "Restart debugging",           cmdRestart},
    {"pause",         "Pause debug mode",            cmdPause},
    {"continue,c",    "Continue execution",          cmdContinue},
    {"stop",          "Stop debug mode",             cmdStop},
    {"next,n",        "Step over one line",          cmdNext},
    {"step,s",        "Step into next line",         cmdStep},
    {"breakpoint,b",  "Set a breakpoint",            cmdBreakpoint},
    {"delete,d",      "Delete a breakpoint",         cmdDelete},
    {"info,i",        "Show program information",    cmdInfo},
    {"target",        "Manage debug target mode",    cmdTarget},
    {"monitor",       "Send a remote monitor command", cmdMonitor},
    {"packet",        "Send a raw remote packet",    cmdPacket},
    {"readmem",       "Read memory from the backend", cmdReadMem},
    {"symbol-file",   "Load ELF symbols for labels",  cmdSymbolFile},
};

static void cmdHelp(const std::vector<std::string>&) {
    consoleWrite("Available commands:");
    for (const auto& def : commandDefs) {
        std::string names(def.names);
        std::string formatted;
        size_t pos = 0;
        while (pos < names.size()) {
            size_t comma = names.find(',', pos);
            if (comma == std::string::npos) comma = names.size();
            if (!formatted.empty()) formatted += ", ";
            formatted += names.substr(pos, comma - pos);
            pos = comma + 1;
        }
        while (formatted.size() < 22) formatted += ' ';
        consoleWrite("  " + formatted + def.description);
    }
}

static void registerCommands() {
    commands.clear();
    for (const auto& def : commandDefs) {
        std::string names(def.names);
        size_t pos = 0;
        while (pos < names.size()) {
            size_t comma = names.find(',', pos);
            if (comma == std::string::npos) comma = names.size();
            std::string name = names.substr(pos, comma - pos);
            commands[name] = {def.description, "", def.handler};
            pos = comma + 1;
        }
    }
}

// ============================================================
// Command execution
// ============================================================
static void executeCommand(const std::string& input) {
    consoleWrite(">>> " + input);

    // Parse command name and rest
    auto spacePos  = input.find(' ');
    std::string cmdName = toLowerCase(
        (spacePos != std::string::npos) ? input.substr(0, spacePos) : input);
    std::string argStr =
        (spacePos != std::string::npos) ? input.substr(spacePos + 1) : "";

    std::vector<std::string> args;
    if (!argStr.empty()) {
        splitStringExpressions(argStr, args);
    }

    auto it = commands.find(cmdName);
    if (it != commands.end()) {
        it->second.handler(args);
    } else {
        consoleWrite("Unknown command: " + cmdName + ". Type 'help' for available commands.");
    }

    autoScroll = true;
}

// ============================================================
// History callback for input text
// ============================================================
static int historyCallback(ImGuiInputTextCallbackData* data) {
    if (data->EventFlag == ImGuiInputTextFlags_CallbackHistory) {
        const int prevHistoryPos = historyPos;
        if (data->EventKey == ImGuiKey_UpArrow) {
            if (historyPos == -1) {
                historyPos = static_cast<int>(commandHistory.size()) - 1;
            } else if (historyPos > 0) {
                historyPos--;
            }
        } else if (data->EventKey == ImGuiKey_DownArrow) {
            if (historyPos != -1 && historyPos < static_cast<int>(commandHistory.size()) - 1) {
                historyPos++;
            } else {
                historyPos = -1;
            }
        }

        if (prevHistoryPos != historyPos) {
            const char* text = (historyPos >= 0) ? commandHistory[historyPos].c_str() : "";
            data->DeleteChars(0, data->BufTextLen);
            data->InsertChars(0, text);
        }
    }
    return 0;
}

// ============================================================
// Console window UI
// ============================================================
void consoleWindow() {
    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[JetBrainsMono20]);

    const float footerHeightToReserve =
        ImGui::GetStyle().ItemSpacing.y + ImGui::GetFrameHeightWithSpacing();

    // --- Output region (selectable, copyable) ---

    ImGui::BeginChild("ScrollingRegion", ImVec2(0, -footerHeightToReserve),
                      ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);

    if (firstRender) {
        registerCommands();
        consoleWrite(">>> Type 'help' to get the list of all available commands.");
        consoleWrite(">>> Active target mode: " + std::string(remote_gdb::useRemoteDebugging() ? "remote gdb" : "local emulation"));
        firstRender = false;
    }

    if (bufferDirty) {
        std::lock_guard<std::mutex> lock(consoleOutputMutex);
        size_t len = consoleOutput.length();
        if (len > sizeof(displayBuffer) - 1) {
            size_t cutoff = len - (sizeof(displayBuffer) - 1);
            size_t newlinePos = consoleOutput.find('\n', cutoff);
            if (newlinePos != std::string::npos && newlinePos + 1 < len) {
                len -= (newlinePos + 1);
                memcpy(displayBuffer, consoleOutput.c_str() + newlinePos + 1, len);
            } else {
                len = sizeof(displayBuffer) - 1;
                memcpy(displayBuffer, consoleOutput.c_str() + cutoff, len);
            }
        } else {
            memcpy(displayBuffer, consoleOutput.c_str(), len);
        }
        displayBuffer[len] = '\0';
        bufferDirty = false;
    }

    const float availWidth = ImGui::GetContentRegionAvail().x;

    // Estimate line count for height
    int lineCount = 1;
    for (const char* p = displayBuffer; *p; p++) {
        if (*p == '\n') lineCount++;
    }
    const float textHeight = lineCount * ImGui::GetTextLineHeightWithSpacing() +
                             ImGui::GetStyle().FramePadding.y * 2;

    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImColor(24, 25, 38, 255).Value);
    ImGui::InputTextMultiline("##ConsoleOutput", displayBuffer, sizeof(displayBuffer),
                              ImVec2(availWidth, textHeight),
                              ImGuiInputTextFlags_ReadOnly);
    ImGui::PopStyleColor();

    // Auto-scroll logic
    if (autoScroll) {
        ImGui::SetScrollHereY(1.0f);
    }
    // Detect manual scroll-up
    if (ImGui::GetScrollMaxY() > 0.0f &&
        ImGui::GetScrollY() < ImGui::GetScrollMaxY() - 20.0f) {
        autoScroll = false;
    } else if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 5.0f) {
        autoScroll = true;
    }

    ImGui::EndChild();
    ImGui::Separator();

    // --- Command input region ---
    ImGui::BeginChild("FixedInputRegion", ImVec2(0, footerHeightToReserve),
                      ImGuiChildFlags_None, ImGuiWindowFlags_NoScrollbar);

    static char  input[500]{};
    static bool  reclaimFocus = false;

    ImGui::PushItemWidth(-1);
    if (ImGui::InputText("##Command", input, IM_ARRAYSIZE(input),
                         ImGuiInputTextFlags_EnterReturnsTrue |
                             ImGuiInputTextFlags_CallbackHistory,
                         historyCallback)) {
        std::string cmd(input);
        if (!cmd.empty()) {
            // Add to history (avoid consecutive duplicates)
            if (commandHistory.empty() || commandHistory.back() != cmd) {
                commandHistory.push_back(cmd);
                // Keep history bounded
                if (commandHistory.size() > 200) {
                    commandHistory.erase(commandHistory.begin());
                }
            }
            historyPos = -1;

            executeCommand(cmd);
            input[0] = '\0';
            reclaimFocus = true;
        }
    }

    ImGui::SetItemDefaultFocus();
    if (reclaimFocus) {
        ImGui::SetKeyboardFocusHere(-1);
        reclaimFocus = false;
    }

    ImGui::PopItemWidth();
    ImGui::EndChild();
    ImGui::PopFont();
    ImGui::End();
}
