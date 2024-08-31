#include "windows.hpp"
std::vector<std::string> output = {};

std::string convToDec(const std::string& str){
    std::string outStr;
    bool foundHexStr = false;

    for (int i = 0; i < str.length(); i++){
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
        if (isRegisterValid(regName, codeInformation.mode) && (!foundValidReg)){
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
                    if (regInfoMap[regName].first <= 64){
                        registerValue = std::to_string(getRegisterValue(regName, (tempContext != nullptr) ? true : false).eightByteVal);
                    }
                    else if (regInfoMap[regName].first == 128){
                        registerValue = std::to_string(getRegisterValue(regName, (tempContext != nullptr) ? true : false).floatVal);
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
    for (auto &pair: addressLineNoMap){
        if (pair.second == std::to_string(lineNo)){
            auto s (std::strtoul(pair.first.c_str(), nullptr, 10));
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
    auto getSpace = [](int base, const std::string& str, int subNum){
        int len = subNum - (str.length());

        if (len < 0){
            len = 0;
        }

        return std::string(base + (len), ' ');
    };

    if (command[0] == 'b' || (command.starts_with("break")) || command.starts_with("breakpoint")
    || command.starts_with("bp") || command[0]=='d' || command.starts_with("db") || command.starts_with("delete"))
    {
        int lineNo = 0;
        bool removeBP = command[0]=='d' || command.starts_with("db") || command.starts_with("delete");
        std::string outStr{};

        if (!arguments.empty()){
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
        if (arguments[0] == "b" || arguments[0] == "break" || arguments[0] == "breakpoints"){
            if (breakpointLines.empty()){
                output.emplace_back("No breakpoints found.");
                output.emplace_back("Set a new one with the b/bp/breakpoint command!");
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
        else if (arguments[0] == "r" || arguments[0] == "re" || arguments[0] == "registers"){
            std::string s = "Register\t\t\t\t\t\tHex";
            output.emplace_back(s);

            if (arguments.size() > 1){
                if (isRegisterValid(toUpperCase(arguments[1]), codeInformation.mode)){
                    std::string regName = toUpperCase(arguments[1]);
                    if (registerValueMap.contains(regName)){
                        output.emplace_back(regName + getSpace(12, regName, 4) + registerValueMap[regName]);
                    }
                    else{
                        if (!getRegisterValue(regName, false).info.is256bit && (!getRegisterValue(regName, false).info.is128bit)){
                            output.emplace_back(regName + getSpace(12, regName, 4) + std::to_string(getRegisterValue(regName, false).eightByteVal));
                        }
                        else{
                           if (getRegisterValue(regName, false).info.is128bit){
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
                                       output.emplace_back(outStr + getSpace(20, outStr, 12) + std::to_string(getRegisterValue(regName, false).info.arrays.floatArray[i]));
                                       outStr.clear();
                                       outStr = "";
                                   }
                               }
                               else{
                                   for (int i = 0; i < 2; i++){
//                                       output.emplace_back(regName + std::to_string() + getSpace(12, regName) + std::to_string(getRegisterValue(regName, false).info.arrays.doubleArray[i]));
                                   }
                               }
                           }
                           else{
                               if (use32BitLanes){
                                   int firstLaneNum = 0;
                                   std::string outStr;
                                   for (int i = 0; i < 8; i++){
                                       outStr += regName + "[";
                                       outStr += std::to_string(firstLaneNum);
                                       outStr += ":";
                                       firstLaneNum = (32 * i);
                                       outStr += std::to_string(firstLaneNum - 1);
                                       outStr += "]";
                                       output.emplace_back(outStr + getSpace(20, outStr, 4) + std::to_string(getRegisterValue(regName, false).info.arrays.floatArray[i]));
                                       outStr.clear();
                                       outStr = "";
                                   }
                               }
                               else{
                                   for (int i = 0; i < 4; i++){
//                                       output.emplace_back(regName + std::to_string() + getSpace(12, regName) + std::to_string(getRegisterValue(regName, false).info.arrays.doubleArray[i]));
                                   }
                               }
                           }
                        }
                    }
                    return;
                }
            }

            for (auto& i: registerValueMap){
                output.emplace_back(i.first + getSpace(12, i.first, 4) + i.second);
            }
        }
    }
}

void consoleWindow()
{
    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[JetBrainsMono20]);

    const float footer_height_to_reserve = ImGui::GetStyle().ItemSpacing.y + ImGui::GetFrameHeightWithSpacing();

    ImGui::BeginChild("ScrollingRegion", ImVec2(0, -footer_height_to_reserve), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);

    for (auto &t : output) {
        ImGui::TextUnformatted(t.c_str());
    }

    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
        ImGui::SetScrollHereY(1.0f);

    ImGui::EndChild();

    ImGui::Separator();

    ImGui::BeginChild("FixedInputRegion", ImVec2(0, footer_height_to_reserve), ImGuiChildFlags_None, ImGuiWindowFlags_NoScrollbar);

    static char input[500]{};
    static bool reclaim_focus = false;

    ImGui::PushItemWidth(-1);  // Make the input box take the full width
    if (ImGui::InputText("##Command", input, IM_ARRAYSIZE(input),
                         ImGuiInputTextFlags_EnterReturnsTrue))
    {
        output.emplace_back(">>> " + (const std::string)input);
        parseCommands(input);
        input[0] = '\0';
        reclaim_focus = true;
    }

    // Auto-focus on window apparition
    ImGui::SetItemDefaultFocus();
    if (reclaim_focus)
    {
        ImGui::SetKeyboardFocusHere(-1); // Auto focus previous widget
        reclaim_focus = false;
    }

    ImGui::PopItemWidth();
    ImGui::EndChild();

    ImGui::PopFont();
    ImGui::End();
}