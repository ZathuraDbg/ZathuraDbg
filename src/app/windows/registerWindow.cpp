#include "windows.hpp"
#include <cstring>
bool codeHasRun = false;
bool stepClickedOnce = false;
tsl::ordered_map<std::string, std::string> registerValueMap{};
std::unordered_map<std::string, std::string> tempRegisterValueMap = {};
std::string hoveredReg;
std::string reg32BitFirstElemStr = "[0:31]";
std::string reg64BitFirstElemStr = "[0:63]";

const std::vector<std::string> reg32BitLaneStrs = {"[0:31]", "[32:63]", "[64:95]", "[96:127]", "[128:159]", "[160:191]", "[192:223]", "[224:255]"};
const std::vector<std::string> reg64BitLaneStrs = {"[0:63]", "[64:127]", "[128:191]", "[192:255]"};

void initDefaultRegs(){
    for (auto& reg: defaultShownRegs){
        registerValueMap[reg] = "0x00";
    }
}

void removeRegisterFromView(const std::string& reg, const bool is128Bits){
    // if it's not 128 bits it's 256 bits

    if (use32BitLanes){
        auto regIDX =  registerValueMap.find(reg + (reg32BitLaneStrs[0]));
        if (regIDX != registerValueMap.end()){
            for (int i = (is128Bits ? 3 : 7); i >= 0; i--){
                if (registerValueMap.end() != regIDX + i) {
                    registerValueMap.erase(regIDX+i);
                }
            }
            return;
        }
    }
    else{
        auto regIDX =  registerValueMap.find(reg + reg64BitLaneStrs[0]);

        if (regIDX != registerValueMap.end()){
            for (int i = (is128Bits ? 1 : 3); i > -1; i--){
                registerValueMap.erase(regIDX+i);
            }
            return;
        }
    }
}


void updateRegs(bool useTempContext){
    std::stringstream hex;
    registerValueInfoT val;
    bool useSecondVal = false;
    for (auto [name, value]: registerValueMap) {
        if (!isRegisterValid(toUpperCase(name), codeInformation.mode)){
            continue;
        }


        if (useTempContext){
            val = getRegister(toLowerCase(name), true);
        }
        else{
            val = getRegister(toLowerCase(name));
        }

        auto const [isRegValid, registerValue] = val;

        if (isRegValid){
            if (registerValue.doubleVal == 0 && registerValue.eightByteVal == 0 && registerValue.floatVal == 0){
                if (registerValue.info.is128bit || registerValue.info.is256bit){
                    hex << "0.00";
                }
                else{
                    hex << "0x00";
                }
            }
            else{
                if (name.contains('[') && name.contains(']') && name.contains(':')){
                    name =  name.substr(0, name.find_first_of('['));
                }
                if (regInfoMap[toUpperCase(name)].first <= 64){
                    hex << "0x";
                    hex << std::hex << registerValue.eightByteVal;
                }
                else if (regInfoMap[toUpperCase(name)].first == 128 || regInfoMap[toUpperCase(name)].first == 256){
                    if (registerValue.info.is128bit){
                        if (!use32BitLanes){
                            if (registerValueMap.contains(name + reg64BitLaneStrs[0])) {
                                hex << std::to_string(registerValue.info.arrays.doubleArray[0]);
                                registerValueMap[name + reg64BitLaneStrs[0]] = hex.str();
                                hex.str("");
                                hex.clear();
                            }
                            if (registerValueMap.contains(name + reg64BitLaneStrs[1])) {
                                hex << std::to_string(registerValue.info.arrays.doubleArray[1]);
                                registerValueMap[name + reg64BitLaneStrs[1]] = hex.str();
                                hex.str("");
                                hex.clear();
                            }
                            continue;
                        }
                        else{
                            for (int i = 0; i < 4; i++){
                                if (registerValueMap.contains(name + reg32BitLaneStrs[i])) {
                                    registerValueMap[name + reg32BitLaneStrs[i]] = std::to_string(registerValue.info.arrays.floatArray[i]);
                                }
                            }
                            hex.str("");
                            hex.clear();
                            continue;
                        }
                    }
                    else if (registerValue.info.is256bit){
                        if (!use32BitLanes){
                            for (int i = 0; i < 4; i++){
                                if (registerValueMap.contains(name + reg64BitLaneStrs[i])) {
                                    registerValueMap[name + reg64BitLaneStrs[i]] = std::to_string(registerValue.info.arrays.doubleArray[i]);
                                }
                            }
                            hex.str("");
                            hex.clear();
                            continue;
                        }
                        else{
                            for (int i = 0; i < 8; i++){
                                if (registerValueMap.contains(name + reg64BitLaneStrs[i])) {
                                    registerValueMap[name + reg32BitLaneStrs[i]] = std::to_string(registerValue.info.arrays.floatArray[i]);
                                }
                            }
                            useSecondVal = false;
                            hex.str("");
                            hex.clear();
                            continue;
                        }
                    }
                }
            }
        }
        else {
            hex << "0x00";
        }

        registerValueMap[name] = hex.str();
        hex.str("");
        hex.clear();
    }
}

std::vector<std::string> parseRegisters(std::string registerString){
    std::vector<std::string> registers = {};
    uint16_t index = 0;

    size_t registerCount = std::count(registerString.begin(), registerString.end(), ',') + 1;
    // the string only contains one register
    if (registerCount == 0){
        registers.emplace_back(registerString);
        return registers;
    }

    registers.resize(registerCount);

    for (auto c: registerString){
        if (c != ',' && c != ' '){
            registers[index] += c;
        }

        if (c == ','){
            index++;
        }
    }
    return registers;
}


int decimalCallback(ImGuiInputTextCallbackData* data) {
    if (data->EventFlag == ImGuiInputTextFlags_CallbackCharFilter)
    {
        if (data->EventChar < 256)
        {
            char c = (char)data->EventChar;
            if (isdigit(c) || c == '.')
            {
                return 0; // Allow the character
            }
        }
        return 1;
    }

    return 1;
}

int checkHexCharsCallback(ImGuiInputTextCallbackData* data)
{
    if (data->EventFlag == ImGuiInputTextFlags_CallbackCharFilter)
    {
        if (data->EventChar < 256)
        {
            char c = (char)data->EventChar;
            if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))
            {
                return 0; // Allow the character
            }
        }
        return 1;
    }

    if (data->EventFlag == ImGuiInputTextFlags_CallbackAlways)
    {
        std::string input(data->Buf, data->BufTextLen);

        if (input.length() >= 2 && input.substr(0, 2) != "0x")
        {
            data->DeleteChars(0, 2);
            data->InsertChars(0, "0x");
            return 1;
        }

        if (input == "0x")
        {
            return 0;
        }

        for (int i = 2; i < input.length(); i++)
        {
            input[i] = std::tolower(input[i]);
        }

        if (input != std::string(data->Buf, data->BufTextLen))
        {
            data->DeleteChars(0, data->BufTextLen);
            data->InsertChars(0, input.c_str());
            return 1;
        }
    }

    return 0;
}

bool contextShown = false;
void registerContextMenu(){
    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[RubikRegular16]);
    if (ImGui::BeginPopupContextItem("RegisterContextMenu")) {
        contextShown = true;
        ImGui::PushID("HideRegOpt");
        if (ImGui::MenuItem("Hide register")) {
            if (regInfoMap[hoveredReg].first == 128){
                removeRegisterFromView(hoveredReg);
            }
            else if (regInfoMap[hoveredReg].first == 512){
                removeRegisterFromView(hoveredReg, false);
            }
            else{
                auto id = registerValueMap.find(hoveredReg);
                if (id != registerValueMap.end()){
                    registerValueMap.erase(id);
                }
            }
        }
        ImGui::PopID();
        ImGui::Separator();
        ImGui::PushID("CopyNameOpt");
        if (ImGui::MenuItem("Copy name")) {
            ImGui::SetClipboardText(hoveredReg.c_str());
        }
        ImGui::PopID();
        ImGui::Separator();
        ImGui::PushID("CopyValueOpt");
        if (ImGui::MenuItem("Copy value")) {
            ImGui::SetClipboardText(registerValueMap[hoveredReg].c_str());
        }
        ImGui::PopID();
        ImGui::Separator();
        ImGui::PushID("ToggleLanesOpt");
        if (ImGui::MenuItem("Toggle lanes")) {
            use32BitLanes = !use32BitLanes;
        }
        ImGui::PopID();
        ImGui::Separator();
        ImGui::EndPopup();
    }
    ImGui::PopFont();
}

uint64_t hexStrToInt(const std::string& val){
    const uint64_t ret = std::strtoul(val.c_str(), nullptr, 16);
    return ret;
};

void registerCommandsUI(){
    const float footer_height_to_reserve = ImGui::GetStyle().ItemSpacing.y + ImGui::GetFrameHeightWithSpacing();

    ImGui::BeginChild("ScrollingRegion", ImVec2(0, -footer_height_to_reserve), false, ImGuiWindowFlags_None);
    ImGui::EndChild();

    std::string registerString;
    char input[500] = {};

    ImGui::PushID(&input);
    ImGui::Text("Toggle registers: ");
    ImGui::SameLine();

    if (ImGui::InputText("##registerInput", input, IM_ARRAYSIZE(input), ImGuiInputTextFlags_EnterReturnsTrue)) {
        registerString += toLowerCase(input);
        LOG_DEBUG("Request to toggle the register: " << input);
    }

    if (!registerString.empty()) {
        auto regs = parseRegisters(registerString);
        std::string regValue;
        std::vector<std::string> regValues;
        bool isRegister128Bits = false;
        bool isRegister256Bits = false;

        for (auto& reg : regs) {
            if (!regInfoMap.contains(toUpperCase(reg))) {
                return;
            }
            auto regInfo = getRegister(reg);
            reg = toUpperCase(reg);
            if (regInfo.out) {
                if (regInfoMap[reg].first <= 64){
                    regValue= std::to_string(regInfo.registerValueUn.eightByteVal);
                }
                else if (regInfoMap[reg].first == 128 ){
                    for (int i = 0; i < (use32BitLanes ? 4 : 2); i++){
                        regValues.push_back(std::to_string(use32BitLanes ? regInfo.registerValueUn.info.arrays.floatArray[i] : regInfo.registerValueUn.info.arrays.doubleArray[i]));
                    }

                    regValue = regValues[0];
                    isRegister128Bits = true;
                }
                else if (regInfoMap[reg].first == 256){
                    if (use32BitLanes){
                        for (const float i : regInfo.registerValueUn.info.arrays.floatArray){
                            regValues.push_back(std::to_string(i));
                        }
                    }
                    else{
                        for (double i : regInfo.registerValueUn.info.arrays.doubleArray){
                            regValues.push_back(std::to_string(i));
                        }
                    }

                    regValue = regValues[0];
                    isRegister128Bits = false;
                    isRegister256Bits = true;
                }
                else if (regInfoMap[reg].first == 80){
                    LOG_ERROR("ST* registers are not supported yet!");
                    continue;
                }

                LOG_DEBUG("Adding the register " << reg);

//              remove the register if it already exists
                if (registerValueMap.count(reg) != 0 || registerValueMap.count(reg + "[0:31]") || registerValueMap.count(reg + "[0:63]") ){
                    if (isRegister128Bits || isRegister256Bits){
                        removeRegisterFromView(reg, isRegister128Bits);
                        continue;
                    }
                    registerValueMap.erase(reg);
                    continue;
                }

                if (regValue == "0"){
                    regValue = "0x00";
                }

                if (isRegister128Bits){
                    if (!use32BitLanes){
                        registerValueMap[reg + "[0:63]"] = regValues[0];
                        registerValueMap[reg + "[64:127]"] = regValues[1];
                    }
                    else{
                        registerValueMap[reg + "[0:31]"] = regValue[0];
                        registerValueMap[reg + "[32:63]"] = regValue[1];
                        registerValueMap[reg + "[64:95]"] = regValue[2];
                        registerValueMap[reg + "[96:127]"] = regValue[3];
                    }
                }
                else if (isRegister256Bits){
                    if (!use32BitLanes){
                        for (int i = 0; i < 4; i++){
                            registerValueMap[reg + reg64BitLaneStrs[i]] = regValues[i];
                        }
                    }
                    else{
                        for (int i = 0; i < 8; i++){
                            registerValueMap[reg + reg32BitLaneStrs[i]] = regValues[i];
                        }
                    }
                }
                else{
                    registerValueMap[reg] = regValue;
                }
            } else {
                LOG_ERROR("Unable to get the register: " << reg);
            }
        }
    }
}

uint16_t getRegisterActualSize(std::string str){
    if (!(str.contains('[') && str.contains(']') && str.contains(':'))){
        return regInfoMap[str].first;
    }

    str = str.substr(0, str.find_first_of('['));
    return regInfoMap[str].first;
}

void parseRegisterValueInput(const std::string& regName, const char *regValueFirst, const bool isBigReg){
    if ((strlen(regValueFirst) != 0)) {
        const uint64_t temp = hexStrToInt(regValueFirst);

        if (strncmp(regValueFirst, "0x", 2) != 0 && !isBigReg) {
            registerValueMap[regName] = "0x";
            registerValueMap[regName].append(regValueFirst);

        } else {
            registerValueMap[regName] = regValueFirst;
        }

        if (codeHasRun)
        {
            if (isBigReg){
                const std::string realRegName = regName.substr(0, regName.find_first_of('['));
                const std::string laneStr = regName.substr(regName.find_first_of('[')+1);
                const int laneNum = std::atoi(laneStr.c_str());
                const auto value = std::string(regValueFirst);

                if (value.contains('.')){
                    int regSize = getRegisterActualSize(regName);
                    if (regSize == 128 || regSize == 256) {
                        uint8_t arrSize = 0;
                        int laneIndex = 0;

                        if (!use32BitLanes){
                            arrSize = (regSize == 128 ? 2 : 4);
                            double arr[arrSize];
                            uc_reg_read(uc, regNameToConstant(realRegName), arr);

                            double val;
                            auto [ptr, ec] = std::from_chars(value.data(), value.data() + value.size(), val);
                            if (ec == std::errc::invalid_argument || ec == std::errc::result_out_of_range){
                                val = 0;
                            }

                            if (laneNum != 0){
                                laneIndex = laneNum / 64;
                            }

                            arr[laneIndex] = val;

                            uc_err err = uc_reg_write(uc, regNameToConstant(realRegName), arr);
                            uc_context_save(uc, context);
                        }
                        else{
                            arrSize = (regSize == 128 ? 4 : 8);
                            float arr[arrSize];
                            uc_reg_read(uc, regNameToConstant(realRegName), &arr);

                            float val;
                            auto [ptr, ec] = std::from_chars(value.data(), value.data() + value.size(), val);

                            if (ec == std::errc::invalid_argument || ec == std::errc::result_out_of_range){
                                val = 0;
                            }

                            if (laneNum != 0){
                                laneIndex = laneNum / 32;
                            }
                            arr[laneIndex] = val;

                            uc_err err = uc_reg_write(uc, regNameToConstant(realRegName), arr);
                            uc_context_save(uc, context);
                        }
                    }
                }
            }
            else{
                uc_reg_write(uc, regNameToConstant(regName), &temp);
                uc_context_save(uc, context);
            }
        }
        else{
            if (regName == getArchIPStr(codeInformation.mode)){
                ENTRY_POINT_ADDRESS = strtoul(regValueFirst, nullptr, 16);
            }
            else if (regName == getArchSBPStr(codeInformation.mode).first || (regName == getArchSBPStr(codeInformation.mode).second)){
                STACK_ADDRESS = strtoul(regValueFirst, nullptr, 16);
            }
            tempRegisterValueMap[regName] = regValueFirst;
        }
    }
}

void registerWindow() {
    if (codeHasRun){
        if (tempContext!= nullptr){
            updateRegs(true);
        }
        else{
            updateRegs();
        }
    }

    if (registerValueMap.empty()){
        initDefaultRegs();
    }

    const auto io = ImGui::GetIO();
    ImGui::PushFont(io.Fonts->Fonts[3]);

    if (ImGui::BeginTable("RegistersTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Register", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Register", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        int index = 0;
        for (auto regValMapInfo = registerValueMap.begin(); regValMapInfo != registerValueMap.end(); ++index) {
            if (!isRegisterValid(toUpperCase(regValMapInfo->first), codeInformation.mode)){
                ++regValMapInfo;
                continue;
            }

            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);

            const float textHeight = ImGui::GetTextLineHeight();
            const float frameHeight = ImGui::GetFrameHeight();
            const float spacing = (frameHeight - textHeight) / 2.0f;

            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + spacing);
            ImGui::PushID(index);

            if (ImGui::Selectable(regValMapInfo->first.c_str(), false)) {
                hoveredReg = regValMapInfo->first;
            }

            if (ImGui::IsItemHovered()){
                hoveredReg = regValMapInfo->first;
            }

            // registerContextMenu();
            ImGui::PopID();

            ImGui::TableSetColumnIndex(1);

            static char regValueFirst[64] = {};
            strncpy(regValueFirst, regValMapInfo->second.c_str(), sizeof(regValueFirst) - 1);
            regValueFirst[sizeof(regValueFirst) - 1] = '\0';

            ImGui::PushID(index * 2);
            ImGui::SetNextItemWidth(-FLT_MIN);

            bool isBigReg = getRegisterActualSize(regValMapInfo->first) > 64;
            const ImGuiTextFlags flags = ImGuiInputTextFlags_CallbackCharFilter;

            registerContextMenu();
            int (*callback)(ImGuiInputTextCallbackData* data) = isBigReg ? decimalCallback: checkHexCharsCallback;
            if (ImGui::InputText(("##regValueFirst" + std::to_string(index)).c_str(), regValueFirst, IM_ARRAYSIZE(regValueFirst), ImGuiInputTextFlags_CharsNoBlank | ImGuiInputTextFlags_EnterReturnsTrue
            | flags, callback)) {
                parseRegisterValueInput(regValMapInfo->first, regValueFirst, isBigReg);
            }
            ImGui::PopID();

            if (std::next(regValMapInfo) == registerValueMap.end()) break;
            if (registerValueMap.find(regValMapInfo->first) == registerValueMap.end()) {
                break;
            }

            ++regValMapInfo;
            if (regValMapInfo == registerValueMap.end()) break;

            ImGui::TableSetColumnIndex(2);
            ImGui::PushID(index + 3 * 4);

            if (ImGui::Selectable(regValMapInfo->first.c_str(), false)) {
                hoveredReg = regValMapInfo->first;
            }

            if (ImGui::IsItemHovered()){
                hoveredReg = regValMapInfo->first;
            }

            ImGui::PopID();

            ImGui::TableSetColumnIndex(3);
            static char regValueSecond[64] = {};
            strncpy(regValueSecond, regValMapInfo->second.c_str(), sizeof(regValueSecond) - 1);
            regValueSecond[sizeof(regValueSecond) - 1] = '\0';

            ImGui::PushID(index * 2 + 1);
            ImGui::SetNextItemWidth(-FLT_MIN);
            registerContextMenu();

            isBigReg = getRegisterActualSize(regValMapInfo->first) > 64;
            int (*callback2)(ImGuiInputTextCallbackData* data) = isBigReg ? decimalCallback: checkHexCharsCallback;
            if (ImGui::InputText(("##value2" + std::to_string(index)).c_str(), regValueSecond, IM_ARRAYSIZE(regValueSecond), ImGuiInputTextFlags_CharsNoBlank | ImGuiInputTextFlags_EnterReturnsTrue | flags, callback2)) {
                parseRegisterValueInput(regValMapInfo->first, regValueSecond, isBigReg);
            }

            ImGui::PopID();
            if (std::next(regValMapInfo) == registerValueMap.end()) break;
            if (registerValueMap.find(regValMapInfo->first) == registerValueMap.end()) {
                break;
            }
            ++regValMapInfo;
            if (regValMapInfo == registerValueMap.end()) break;
        }

        ImGui::EndTable();
    }

    registerCommandsUI();

    ImGui::PopID();
    ImGui::PopFont();
}