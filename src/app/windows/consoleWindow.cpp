#include "windows.hpp"
std::vector<std::string> output = {};

std::string convToDec(const std::string& str){
    std::string outStr;
    bool foundHexStr = false;

    for (size_t i = 0; i < str.length(); i++){
        if (str[i] == '0' && (str[i+1] == 'x' || str[i+1] == 'X' )){
            i++;
            foundHexStr = true;
            continue;
        }

        if (foundHexStr){
            char* endptr = nullptr;
            auto convVal = strtoul(str.substr(i).c_str(), &endptr, 16);
            size_t diff = endptr - str.substr(i).c_str() - 1;
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
    double rounded = std::round(d);

    if (rounded < 0 || rounded > static_cast<double>(std::numeric_limits<uint64_t>::max())) {
        return 0;
    }

    return static_cast<uint64_t>(rounded);
}

std::string parseVals(std::string val){
    std::string result;
    std::string regName;
    std::vector<std::string> regNames = {};
    bool foundReg = false;
    bool foundValidReg = false;
    auto len = val.length();

    size_t i = 0;
    val = toUpperCase(val);
    val += " ";
    for (auto& c: val){
        if (isRegisterValid(regName) && (!foundValidReg)){
            foundValidReg = true;
        }

        if (foundValidReg){
            if (c == ' ' || c == '$' || c == '+' || c =='-' || c == '/' || c == '*' || (i == len)){
                foundReg = false;
                foundValidReg = false;
                regNames.push_back(regName);
                std::string registerValue;
                if (!codeHasRun){
                    registerValue = tempRegisterValueMap[regName];
                }
                else{
                    if (regInfoMap[regName] <= 64){
                        registerValue = std::to_string(getRegisterValue(regName).eightByteVal);
                    }
                    else if (regInfoMap[regName] == 128){
                        registerValue = std::to_string(getRegisterValue(regName).floatVal);
                    }
                }

                if (registerValue.starts_with("0x")){
                     result += std::to_string(hexStrToInt(registerValue));
                }
                else{
                    result += registerValue;
                }

                if (result.empty()){
                    result += "0";
                }

                if (c!=' '){
                    result += c;
                }

                regName.clear();
                i++;
                continue;
            }
            else{
                regName.clear();
            }
        }

        if (c == '$'){
            foundReg = true;
            i++;
            continue;
        }

        if (foundReg){
            regName += c;
        }

        if (c != ' ' && (!foundReg)){
            result += c;
        }

        i++;
    }

    return std::to_string(doubleToUint64(te_interp(convToDec(result).data(), nullptr)));
}

void splitStringExpressions(std::string stringToSplit,std::vector<std::string>& stringVec){
    std::string strToPush{};
    stringToSplit+=' ';
    for (int j = 0; j < stringToSplit.length(); j++){
        char i = stringToSplit[j];

        if (i == '+' || i == '-' || i == '*' || i == '/'){
            if (!strToPush.empty()){
                stringVec.emplace_back(strToPush);
                strToPush.clear();
                strToPush = "";
            }
            stringVec.emplace_back(std::string(1, i));
            continue;
        }

        if (i == ' '){
            if (!strToPush.empty()){
                stringVec.emplace_back(strToPush);
                strToPush.clear();
                strToPush = "";
            }
            continue;
        }

        strToPush += i;
    }
}

std::string getAddressFromLineNo(int lineNo){
    for (auto &[fst, snd]: addressLineNoMap){
        if (snd == std::to_string(lineNo)){
            const auto s (std::strtoul(fst.c_str(), nullptr, 10));
            std::stringstream result;
            result << "0x" << std::setfill('0') << std::hex << s;
            return " at " + result.str();
        }
    }
    return "";
}

int parseBreakpointArgs(std::vector<std::string>& arguments, const std::string& argument, std::string &outStr){
    const std::regex labelPattern("^[a-zA-Z_][a-zA-Z0-9_]*$");
    int lineNo = 0;
    if (arguments[0].starts_with("0x") || arguments[0].starts_with('$')){
        lineNo = std::atoi(addressLineNoMap[parseVals(argument)].c_str());
        outStr += "address " + std::to_string(lineNo);
    }
    else if (std::regex_match(arguments[0], labelPattern)){
        if (labelLineNoMapInternal.count(arguments[0]) != 0){
            lineNo = labelLineNoMapInternal[arguments[0]] + 1;
        }

        outStr += "label " + arguments[0] + " at line no. " + std::to_string(lineNo);
    }
    else if (std::all_of(arguments[0].begin(), arguments[0].end(), ::isdigit)){
        lineNo = std::atoi(parseVals(argument).c_str());
        outStr += "line number " + std::to_string(lineNo) + getAddressFromLineNo(lineNo);
    }

    return lineNo;
}

void parseCommands(const std::string& commandIn){
    std::string command = toLowerCase(commandIn);
    std::vector<std::string> arguments;
    std::string argument;


    auto idx = command.find_first_of(' ');
    if (idx != std::string::npos) {
        argument = command.substr(idx);
    }

    splitStringExpressions(argument, arguments);
    auto getSpace = [](const int base, const std::string& str, const int subNum){
        int len = subNum - (str.length());

        if (len < 0){
            len = 0;
        }

        return std::string(base + (len), ' ');
    };

    if (command.starts_with("breakpoint") || command.starts_with("b")
        || command[0]=='d' || command.starts_with("delete"))
    {
        bool removeBP = command[0]=='d' || command.starts_with("delete");
        std::string outStr{};

        if (!arguments.empty()){
            int lineNo = 0;
            lineNo = parseBreakpointArgs(arguments, argument, outStr);

            if (removeBP){
                if (debugRemoveBreakpoint(lineNo - 1)){
                    output.emplace_back("Deleted breakpoint at line " + outStr);
                }
                else{
                    output.emplace_back("No breakpoint at " + outStr);
                }
            }
            else{
                if (debugAddBreakpoint(lineNo - 1)){
                    output.emplace_back("Added breakpoint at " + outStr);
                }
                else{
                    output.emplace_back("Breakpoint at " + outStr + " already exists!");
                }
            }
        }
    }
    else if (command[0] == 'i' || command.starts_with("info")){
        if (arguments[0] == "b" || arguments[0] == "breakpoints"){
            if (breakpointLines.empty()){
                output.emplace_back("No breakpoints found.");
                output.emplace_back("Set a new one with the b/breakpoint command!");
            }
            else{
                std::string s = "Num\t\tLine\t\tAddress";
                output.emplace_back(s);
                int j = 0;
                for (auto &i: breakpointLines){
                    output.emplace_back(std::to_string(j) + getSpace(10, std::to_string(i), 4) + std::to_string(i) + "       " + getAddressFromLineNo(i));
                    j++;
                }
            }
        }
        else if (arguments[0] == "r" || arguments[0] == "registers"){
            std::string s = "Register\t\t\t\t\t\tHex";

            if (arguments.size() > 1){
                if (isRegisterValid(toUpperCase(arguments[1]))){
                    if (std::string regName = toUpperCase(arguments[1]); registerValueMap.contains(regName)){
                        output.emplace_back(s);
                        output.emplace_back(regName + getSpace(12, regName, 4) + registerValueMap[regName]);
                    }
                    else{
                        if (!getRegisterValue(regName).info.is256bit && (!getRegisterValue(regName).info.is128bit)){
                            output.emplace_back(s);
                            output.emplace_back(regName + getSpace(12, regName, 4) + std::to_string(getRegisterValue(regName).eightByteVal));
                        }
                        else{
                           if (getRegisterValue(regName).info.is128bit){
                               output.emplace_back(s);
                               if (use32BitLanes){
                                   int firstLaneNum = 0;
                                   std::string outStr;
                                   for (int i = 0; i < 4; i++){
                                       outStr += regName + "[";
                                       outStr += std::to_string(firstLaneNum);
                                       outStr += ":";
                                       firstLaneNum = (32 + 32 * i);
                                       outStr += std::to_string(firstLaneNum - 1);
                                       outStr += "]";
                                       output.emplace_back(outStr + getSpace(20, outStr, 12) + std::to_string(getRegisterValue(regName).info.arrays.floatArray[i]));
                                       outStr.clear();
                                       outStr = "";
                                   }
                               }
                               else{
                                   int firstLaneNum = 0;
                                   std::string outStr;

                                   for (int i = 0; i < 2; i++){
                                          outStr += regName + "[";
                                           outStr += std::to_string(firstLaneNum);
                                           outStr += ":";
                                           firstLaneNum = (64 + 64 * i);
                                           outStr += std::to_string(firstLaneNum - 1);
                                           outStr += "]";
                                           output.emplace_back(outStr + getSpace(20, outStr, 12) + std::to_string(getRegisterValue(regName).info.arrays.doubleArray[i]));
                                           outStr.clear();
                                           outStr = "";
                                       }
                               }
                           }
                           else{
                               s = "Register\t\t\t\t\t\t Hex";

                               output.emplace_back(s);
                               if (use32BitLanes){
                                   int firstLaneNum = 0;
                                   std::string outStr;
                                   for (int i = 0; i < 8; i++){
                                       outStr += regName + "[";
                                       outStr += std::to_string(firstLaneNum);
                                       outStr += ":";
                                       firstLaneNum = (32 + 32 * i);
                                       outStr += std::to_string(firstLaneNum - 1);
                                       outStr += "]";
                                       output.emplace_back(outStr + getSpace(20, outStr, 13) + std::to_string(getRegisterValue(regName).info.arrays.floatArray[i]));
                                       outStr.clear();
                                       outStr = "";
                                   }
                               }
                               else{
                                   int firstLaneNum = 0;
                                   std::string outStr;
                                   for (int i = 0; i < 4; i++){
                                       outStr += regName + "[";
                                       outStr += std::to_string(firstLaneNum);
                                       outStr += ":";
                                       firstLaneNum = (64 + 64 * i);
                                       outStr += std::to_string(firstLaneNum - 1);
                                       outStr += "]";
                                       output.emplace_back(outStr + getSpace(20, outStr, 13) + std::to_string(getRegisterValue(regName).info.arrays.doubleArray[i]));
                                       outStr.clear();
                                       outStr = "";
                                   }
                               }
                           }
                        }
                    }
                    return;
                }
            }

            s = "Register\t\tHex";
            output.emplace_back(s);
            for (const auto&[registerName, value]: registerValueMap){
                output.emplace_back(registerName + getSpace(12, registerName, 4) += value);
            }
        }
        else if (arguments[0] == "l" || arguments[0].starts_with("labels")){
            auto s = "Num\t Name\t\t\t\tLine\t\tAddress";
            output.emplace_back(s);
            std::string outStr;
            int j = 1;
            for (auto& i: labelLineNoMapInternal){
                outStr = std::to_string(j);
                outStr += getSpace(7, i.first, 4);
                outStr += i.first;
                outStr += getSpace(4, (i.first), 16);
                outStr += std::to_string(i.second);
                outStr += getSpace(4, std::to_string(i.second), 7);
                outStr += getAddressFromLineNo(i.second+1);
                output.push_back(outStr);
                j++;
                outStr.clear();
            }
        }
    }
    else if ((command[0] == 's' && command.length() == 1) || command == "step"){
        debugStepIn = true;
    }
    else if ((command[0] == 'n' && command.length() == 1) || command == "next"){
        debugStepOver = true;
    }
    else if ((command[0] == 'r' && command.length() == 1 )|| command == "run"){
        debugRun = true;
    }
    else if (command == "start"){
        enableDebugMode = true;
    }
    else if (command == "restart" || command == "re"){
        debugRestart = true;
    }
    else if (command == "pause"){
        debugPause = true;
    }
    else if (command == "continue"){
        debugContinue = true;
    }
    else if (command == "stop"){
        debugStop = true;
    }
    else if (command.starts_with("help")) {
        output.emplace_back( "List of commands:\n");
        output.emplace_back("help:  Show this message.\n");
        output.emplace_back("run, r:  Runs the assembly code.\n");
        output.emplace_back("start:  Starts the debug mode.\n");
        output.emplace_back("restart:  Restarts the debugging mode.\n");
        output.emplace_back("pause:  Pauses the debug mode.\n");
        output.emplace_back("continue:  Continue debugging.\n");
        output.emplace_back("stop:  Stops the debug mode.\n");
        output.emplace_back("next, n:  Performs step over one line.\n");
        output.emplace_back("step, s:  Performs step in into next line.\n");
        output.emplace_back("pause:  Pauses the debug mode.\n");
        output.emplace_back("labels, l: List all the labels in the program.\n");
        output.emplace_back("info, i: Shows information of the program state.\n");
        output.emplace_back("\tregisters, r: Show values of all shown registers.\n");
        output.emplace_back("\tregisters, r <regName>: Show the value of the register regName.\n");
        output.emplace_back("\tbreakpoint, b: Show all the currently set breakpoints.\n");
        output.emplace_back("breakpoint, b <n>: Set a breakpoint on the line n.\n");
        output.emplace_back("delete, d <n>: Delete breakpoint on the line n.\n");
    }
    else {
        return;
    }
}

void consoleWindow()
{
    static bool isDefaultMessageShown = false;
    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[JetBrainsMono20]);
    const float footerHeightToReserve = ImGui::GetStyle().ItemSpacing.y + ImGui::GetFrameHeightWithSpacing();
    ImGui::BeginChild("ScrollingRegion", ImVec2(0, -footerHeightToReserve), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);

    if (!isDefaultMessageShown) {
        output.emplace_back(">>> Type help to get the list of all the commands that you can use!");
        output.emplace_back(">>> Commands are at very early stage so quality and accuracy is not guaranteed.");
        isDefaultMessageShown = true;
    }

    int i = 1;
    for (auto &t : output) {
        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImColor(24, 25, 38, 255).Value);
        ImGui::PushID(("id" + std::to_string(i)).c_str());
        ImVec2 textSize = ImGui::CalcTextSize(t.c_str());
        textSize.y += 5;
        textSize.x += 7;
        ImGui::InputTextEx("##TextSelection", nullptr, t.data(), t.length(), textSize, ImGuiInputTextFlags_ReadOnly, nullptr, nullptr);
        ImGui::PopID();
        i++;
        ImGui::PopStyleColor();
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
        ImGui::SetScrollHereY(1.0f);
    }

    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
        ImGui::SetScrollHereY(1.0f);

    ImGui::EndChild();
    ImGui::Separator();
    ImGui::BeginChild("FixedInputRegion", ImVec2(0, footerHeightToReserve), ImGuiChildFlags_None, ImGuiWindowFlags_NoScrollbar);

    static char input[500]{};
    static bool reclaimFocus = false;

    ImGui::PushItemWidth(-1);
    if (ImGui::InputText("##Command", input, IM_ARRAYSIZE(input),
                         ImGuiInputTextFlags_EnterReturnsTrue))
    {
        output.emplace_back(">>> " + static_cast<const std::string>(input));
        parseCommands(input);
        input[0] = '\0';
        reclaimFocus = true;
    }

    ImGui::SetItemDefaultFocus();
    if (reclaimFocus)
    {
        ImGui::SetKeyboardFocusHere(-1);
        reclaimFocus = false;
    }

    ImGui::PopItemWidth();
    ImGui::EndChild();
    ImGui::PopFont();
    ImGui::End();
}
