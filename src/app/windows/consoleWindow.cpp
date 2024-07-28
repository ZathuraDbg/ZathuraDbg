#include "windows.hpp"

std::vector<std::string> commands = {};
void parseVals(std::string val){
    std::string result;
    std::string regName;

    std::vector<std::string> regNames = {};
    bool foundReg = false;
    bool foundValidReg = false;
    auto len = val.length();

    size_t i = 0;
    if (val.contains('$')){
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
                    result += std::to_string(getRegisterValue(regName, false));
                    result += c;
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
    if (!regName.empty()){
        regNames.push_back(regName);
    }
    std::cout << result << std::endl;
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
        commands.emplace_back(input);
        parseVals(input);
        input[0] = '\0';
    }

    ImGui::PopFont();
    ImGui::PopID();
    ImGui::End();
}