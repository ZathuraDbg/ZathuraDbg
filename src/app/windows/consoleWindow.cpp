#include "windows.hpp"
std::vector<std::string> commands = {};

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

void parseCommands(const std::string& commandIn){
    std::string command = toLowerCase(commandIn);
    const std::regex labelPattern("^[a-zA-Z_][a-zA-Z0-9_]*$");

    if (command[0] == 'b' || (command.starts_with("break")) || command.starts_with("breakpoint")
    || command.starts_with("bp"))
    {
        int lineNo;
        std::vector<std::string> arguments;
        std::string argument;

        auto idx = command.find_first_of(' ');
        if (idx != std::string::npos){
            argument = command.substr(idx);
            splitStringExpressions(argument, arguments);

            if (arguments[0].starts_with("0x") || arguments[0].starts_with('$')){
                lineNo = std::atoi(parseVals(argument).c_str());
                debugAddBreakpoint(lineNo - 1);
            }
            else if (std::regex_match(arguments[0], labelPattern)){
                if (labelLineNoMapInternal.count(arguments[0]) != 0){
                    lineNo = labelLineNoMapInternal[arguments[0]];
                    debugAddBreakpoint(lineNo);
                }
            }
            else if (std::all_of(arguments[0].begin(), arguments[0].end(), ::isdigit)){
                lineNo = std::atoi(parseVals(argument).c_str());
                debugAddBreakpoint(lineNo - 1);
            }

        }
    }
}

void consoleWindow()
{
    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[SatoshiMedium18]);

    const float footer_height_to_reserve = ImGui::GetStyle().ItemSpacing.y + ImGui::GetFrameHeightWithSpacing();

    // Begin the main scrollable region
    ImGui::BeginChild("ScrollingRegion", ImVec2(0, -footer_height_to_reserve), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);

    // Display previous commands
    for (auto &t : commands) {
        ImGui::TextUnformatted(t.c_str());
    }

    // Keep auto-scrolling if we're already at the bottom
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
        ImGui::SetScrollHereY(1.0f);

    ImGui::EndChild();

    // Separator
    ImGui::Separator();

    // Fixed input area at the bottom
    ImGui::BeginChild("FixedInputRegion", ImVec2(0, footer_height_to_reserve), ImGuiChildFlags_None, ImGuiWindowFlags_NoScrollbar);

    static char input[500]{};
    static bool reclaim_focus = false;

    ImGui::PushItemWidth(-1);  // Make the input box take the full width
    if (ImGui::InputText("##Command", input, IM_ARRAYSIZE(input),
                         ImGuiInputTextFlags_EnterReturnsTrue))
    {
        commands.emplace_back((std::string(input) + ": " + (parseVals(input))));
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