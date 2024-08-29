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

void removeRegisterFromView(const std::string& reg, bool is128Bits = true){
    if (use32BitLanes){
        auto regIDX =  registerValueMap.find(reg + (reg32BitLaneStrs[0]));
        if (regIDX != registerValueMap.end()){
            for (int i = (is128Bits ? 3 : 7); i >= 0; i--){
                registerValueMap.erase(regIDX+i);
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
                            hex << std::to_string(registerValue.info.arrays.doubleArray[0]);
                            registerValueMap[name + reg64BitLaneStrs[0]] = hex.str();
                            hex.str("");
                            hex.clear();
                            hex << std::to_string(registerValue.info.arrays.doubleArray[1]);
                            registerValueMap[name + reg64BitLaneStrs[1]] = hex.str();
                            hex.str("");
                            hex.clear();
                            continue;
                        }
                        else{
                            for (int i = 0; i < 4; i++){
                                registerValueMap[name + reg32BitLaneStrs[i]] = std::to_string(registerValue.info.arrays.floatArray[i]);
                            }
                            hex.str("");
                            hex.clear();
                            continue;
                        }
                    }
                    else if (registerValue.info.is256bit){
                        if (!use32BitLanes){
                            for (int i = 0; i < 4; i++){
                                registerValueMap[name + reg64BitLaneStrs[i]] = std::to_string(registerValue.info.arrays.doubleArray[i]);
                            }
                            hex.str("");
                            hex.clear();
                            continue;
                        }
                        else{
                            for (int i = 0; i < 8; i++){
                                registerValueMap[name + reg32BitLaneStrs[i]] = std::to_string(registerValue.info.arrays.floatArray[i]);
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

int checkHexCharsCallback(ImGuiInputTextCallbackData* data) {
    if (data->BufTextLen < 2){
        return 0;
    }

    std::string input(data->Buf, data->BufTextLen);
    std::string filteredString;

    int i = 0;

    if (toLowerCase(input).starts_with("0x")){
        filteredString += "0x";
        i = 2;
    }
    else{
        input = "0x" + input;
        filteredString += "0x";
        i = 2;
    }

    for (i; i < input.length(); i++){
        if ((input[i] >= '0' && input[i] <= '9') || (input[i] >= 'A' && input[i] <= 'F') || (input[i] >= 'a' && input[i] <= 'f')) {
            filteredString += input[i];
        }
        else{
            filteredString += ' ';
        }
    }

    filteredString.erase(std::remove(filteredString.begin(), filteredString.end(), ' '), filteredString.end());
    data->DeleteChars(0, data->BufTextLen);
    data->InsertChars(0, filteredString.c_str());
    data->BufTextLen = filteredString.length();
    data->CursorPos = data->SelectionStart = data->SelectionEnd = filteredString.length();
    return 0;
}

bool contextShown = false;
void registerContextMenu(){
    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[RubikRegular16]);
    if (ImGui::BeginPopupContextItem("RegisterContextMenu")) {
        contextShown = true;
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
        ImGui::Separator();
        if (ImGui::MenuItem("Copy name")) {
            ImGui::SetClipboardText(registerValueMap[hoveredReg].c_str());
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Copy value")) {
            ImGui::SetClipboardText(hoveredReg.c_str());
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Toggle lanes")) {
            use32BitLanes = !use32BitLanes;
        }
        ImGui::EndPopup();
    }
    ImGui::PopFont();
}

uint64_t hexStrToInt(const std::string& val){
    uint64_t ret;
    ret = std::strtoul(val.c_str(), nullptr, 16);
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
                        for (float i : regInfo.registerValueUn.info.arrays.floatArray){
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

                if (regInfoMap.count(reg) == 0){
                    continue;
                }

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

    auto io = ImGui::GetIO();
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
                regValMapInfo++;
                continue;
            }

            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            float textHeight = ImGui::GetTextLineHeight();
            float frameHeight = ImGui::GetFrameHeight();
            float spacing = (frameHeight - textHeight) / 2.0f;
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + spacing);
            ImGui::PushID(index);  // Use a unique ID for each row
            if (ImGui::Selectable(regValMapInfo->first.c_str(), false)) {
                hoveredReg = regValMapInfo->first;
            }

            if (ImGui::IsItemHovered()){
                hoveredReg = regValMapInfo->first;
            }

            registerContextMenu();
            ImGui::PopID();


            ImGui::TableSetColumnIndex(1);
            static char regValueFirst[64] = {};
            strncpy(regValueFirst, regValMapInfo->second.c_str(), sizeof(regValueFirst) - 1);
            regValueFirst[sizeof(regValueFirst) - 1] = '\0';

            ImGui::PushID(index * 2);
            ImGui::SetNextItemWidth(-FLT_MIN);
            bool isBigReg = getRegisterActualSize(regValMapInfo->first) > 64;
            ImGuiTextFlags flags = isBigReg ? ImGuiInputTextFlags_CallbackCharFilter : ImGuiInputTextFlags_None;
            int (*callback)(ImGuiInputTextCallbackData* data) = isBigReg ? checkHexCharsCallback : nullptr;
            if (ImGui::InputText(("##regValueFirst" + std::to_string(index)).c_str(), regValueFirst, IM_ARRAYSIZE(regValueFirst), ImGuiInputTextFlags_CharsNoBlank | ImGuiInputTextFlags_EnterReturnsTrue
            | flags, callback)) {
                if ((strlen(regValueFirst) != 0)) {
                    uint64_t temp = hexStrToInt(regValueFirst);

                    if (strncmp(regValueFirst, "0x", 2) != 0 && !isBigReg) {
                        registerValueMap[regValMapInfo->first] = "0x";
                        registerValueMap[regValMapInfo->first].append(regValueFirst);

                    } else {
                        registerValueMap[regValMapInfo->first] = regValueFirst;
                    }

                    if (codeHasRun)
                    {
                        if (isBigReg){
//                            void* mem = malloc(getRegisterActualSize(regValMapInfo->first));
//                            uc_reg_read(uc, regNameToConstant(regValMapInfo->first), &mem);
                            std::string realRegName = regValMapInfo->first.substr(0, regValMapInfo->first.find_first_of('['));
                            std::string laneStr = regValMapInfo->first.substr(regValMapInfo->first.find_first_of('[')+1);
                            int laneNum = std::atoi(laneStr.c_str());
                            std::string value = std::string(regValueFirst);
                            int laneIndex = 0;
                            uint8_t arrSize = 0;
                            if (value.contains('.')){
                                int regSize = getRegisterActualSize(regValMapInfo->first);
                                if (regSize == 128 || regSize == 256){

                                    if (!use32BitLanes){
                                        auto valT = getRegisterValue(realRegName, false);
                                        std::cout << valT.info.arrays.doubleArray[0] << std::endl;
                                        std::cout << valT.info.arrays.doubleArray[1] << std::endl;

                                        arrSize = (regSize == 128 ? 2 : 4);
                                        double mem[arrSize];
                                        uc_reg_read(uc, regNameToConstant(regValMapInfo->first), &mem);

                                        double val;
                                        auto result = std::from_chars(value.data(), value.data() + value.size(), val);

                                        if (result.ec == std::errc::invalid_argument || result.ec == std::errc::result_out_of_range){
                                            val = 0;
                                        }

                                        if (laneNum != 0){
                                            laneIndex = laneNum / 64;
                                        }

                                        mem[laneIndex] = val;
                                        uc_err err = uc_reg_write(uc, regNameToConstant(realRegName), mem);
                                        uc_context_save(uc, context);

                                    }
                                    else if (use32BitLanes){
                                        arrSize = (regSize == 128 ? 4 : 8);
                                        uint32_t mem[arrSize];
                                        uc_reg_read(uc, regNameToConstant(regValMapInfo->first), &mem);

                                        float val;
                                        auto result = std::from_chars(value.data(), value.data() + value.size(), val);

                                        if (result.ec == std::errc::invalid_argument || result.ec == std::errc::result_out_of_range){
                                            val = 0;
                                        }
                                        if (laneNum != 0){
                                            laneIndex = laneNum / 32;
                                        }

                                        memcpy(mem + laneIndex, &val, sizeof(val));
                                        uc_reg_write(uc, regNameToConstant(realRegName), mem);
                                    }
                                }
                            }
                        }
                        else{
                            uc_reg_write(uc, regNameToConstant(regValMapInfo->first), &temp);
                            uc_context_save(uc, context);
                        }
                    }
                    else{
                        if (regValMapInfo->first == getArchIPStr(codeInformation.mode)){
                            ENTRY_POINT_ADDRESS = strtoul(regValueFirst, nullptr, 16);
                        }
                        else if (regValMapInfo->first == getArchSBPStr(codeInformation.mode).first || (regValMapInfo->first == getArchSBPStr(codeInformation.mode).second)){
                            STACK_ADDRESS = strtoul(regValueFirst, nullptr, 16);
                        }

                        tempRegisterValueMap[regValMapInfo->first] = regValueFirst;
                    }
                }
            }
            ImGui::PopID();

            if (std::next(regValMapInfo) == registerValueMap.end()) break;
            if (registerValueMap.find(regValMapInfo->first) == registerValueMap.end()) {
                break;
            }
            ++regValMapInfo;
            if (regValMapInfo == registerValueMap.end()) break;
            ImGui::TableSetColumnIndex(2);
            ImGui::PushID(index + 3 * 4);  // Use a unique ID for each ro
            if (ImGui::Selectable(regValMapInfo->first.c_str(), false)) {
                hoveredReg = regValMapInfo->first;
            }

            if (ImGui::IsItemHovered()){
                hoveredReg = regValMapInfo->first;
            }
            registerContextMenu();
            ImGui::PopID();

            ImGui::TableSetColumnIndex(3);
            static char value2[64] = {};
            strncpy(value2, regValMapInfo->second.c_str(), sizeof(value2) - 1);
            value2[sizeof(value2) - 1] = '\0';

            ImGui::PushID(index * 2 + 1);
            ImGui::SetNextItemWidth(-FLT_MIN);
            if (ImGui::InputText(("##value2" + std::to_string(index)).c_str(), value2, IM_ARRAYSIZE(value2), ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_CharsUppercase | ImGuiInputTextFlags_CharsNoBlank | ImGuiInputTextFlags_EnterReturnsTrue)) {
                if ((strlen(value2) != 0)) {

                if (strncmp(value2, "0x", 2) != 0) {
                    registerValueMap[regValMapInfo->first] = "0x";
                    registerValueMap[regValMapInfo->first].append(value2);
                } else {
                    registerValueMap[regValMapInfo->first] = value2;
                }

                uint64_t temp;
                temp = hexStrToInt(value2);

                if (codeHasRun)
                {
                    uc_reg_write(uc, regNameToConstant(regValMapInfo->first), &temp);
                    uc_context_save(uc, context);
                }
                else{
                    if (regValMapInfo->first == getArchIPStr(codeInformation.mode)){
                        ENTRY_POINT_ADDRESS = strtoul(regValueFirst, nullptr, 10);
                    }
                    else{
                        if (regValMapInfo->first == getArchIPStr(codeInformation.mode)){
                            ENTRY_POINT_ADDRESS = strtoul(regValueFirst, nullptr, 16);
                        }
                        else if (regValMapInfo->first == getArchSBPStr(codeInformation.mode).first || (regValMapInfo->first == getArchSBPStr(codeInformation.mode).second)){
                            STACK_ADDRESS = strtoul(regValueFirst, nullptr, 16);
                        }

                        tempRegisterValueMap[regValMapInfo->first] = regValueFirst;
                    }
                }
            }
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