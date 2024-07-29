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

//      "0x 10f0+"
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
    if (val.contains('$')){
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
                    auto registerValue = (!codeHasRun) ? tempRegisterValueMap[regName] : (std::to_string(getRegisterValue(regName, (tempContext != nullptr) ? true : false)));
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
    }
    else{
        return val;
    }

    return std::to_string(doubleToUint64(te_interp(convToDec(result).data(), nullptr)));
}

void consoleWindow()
{
    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[SatoshiMedium18]);
    for (auto &t: commands){
        ImGui::Text("%s", t.c_str());
    }

    const float footer_height_to_reserve = ImGui::GetStyle().ItemSpacing.y + ImGui::GetFrameHeightWithSpacing();
    ImGui::BeginChild("ScrollingRegion", ImVec2(0, -footer_height_to_reserve), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);

    ImGui::EndChild();
    static char input[500]{};

    ImGui::PushID(&input);
     if (ImGui::InputText("Command", input, IM_ARRAYSIZE(input), ImGuiInputTextFlags_EnterReturnsTrue)){
        commands.emplace_back((std::string(input) + ": " + (parseVals(input))));
        input[0] = '\0';
    }

    ImGui::PopFont();
    ImGui::PopID();
    ImGui::End();
}