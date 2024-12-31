#include "windows.hpp"
#include <cstring>
bool codeHasRun = false;
bool stepClickedOnce = false;
tsl::ordered_map<std::string, std::string> registerValueMap{};
std::unordered_map<std::string, std::string> tempRegisterValueMap = {};
std::string hoveredReg;
std::string reg32BitFirstElemStr = "[0:31]";
std::string reg64BitFirstElemStr = "[0:63]";

const std::vector<std::string> reg32BitLaneStrs = {"[0:31]", "[32:63]", "[64:95]", "[96:127]", "[128:159]", "[160:191]", "[192:223]", "[224:255]", "[256:287]", "[288:319]", "[320:351]", "[352:383]", "[384:415]", "[416:447]", "[448:479]", "[480:511]"};
const std::vector<std::string> reg64BitLaneStrs = {"[0:63]", "[64:127]", "[128:191]", "[192:255]", "[256:319]", "[320:383]", "[384:447]", "[448:511]"};

void initDefaultRegs(){
    for (auto& reg: defaultShownRegs){
        registerValueMap[reg] = "0x00";
    }
}

void removeRegisterFromView(const std::string& reg, const int regType){
    bool is128Bits = false, is256bits = false, is512bits = false;

    if (regType == 1) {
        is128Bits = true;
    }
    else if (regType == 2) {
        is256bits = true;
    }
    else if (regType == 3) {
        is512bits = true;
    }

    int8_t comparisonAmount;
    if (use32BitLanes){
            if (is128Bits) {
                comparisonAmount = 4;
            }
            else if (is256bits) {
                comparisonAmount = 8;
            }
            else if (is512bits) {
                comparisonAmount = 16;
            }
            else {
                return;
            }

            const std::string registerName = getRegisterActualName(reg);
            for (int i = 0; i < comparisonAmount; i++) {
                if (registerValueMap.contains(registerName + reg32BitLaneStrs[i])) {
                    registerValueMap.erase(registerName + reg32BitLaneStrs[i]);
                }
            }
    }
    else{
        if (is128Bits) {
            comparisonAmount = 2;
        }
        else if (is256bits) {
            comparisonAmount = 4;
        }
        else if (is512bits) {
            comparisonAmount = 8;
        }
        else {
            return;
        }

        const std::string registerName = getRegisterActualName(reg);
        for (int i = 0; i < comparisonAmount; i++) {
            if (registerValueMap.contains(registerName + reg64BitLaneStrs[i])) {
                registerValueMap.erase(registerName + reg64BitLaneStrs[i]);
            }
        }
    }
}


void updateRegs(bool useTempContext){
    std::stringstream hex;
    registerValueInfoT val;
    bool useSecondVal = false;

    if (!useTempContext) {
        if (context == nullptr) {
            return;
        }
    }
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
                if (registerValue.info.is128bit || registerValue.info.is256bit || registerValue.info.is512bit){
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
                else if (regInfoMap[toUpperCase(name)].first == 128 || regInfoMap[toUpperCase(name)].first == 256 || regInfoMap[toUpperCase(name)].first == 512){
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
                    else if (registerValue.info.is512bit) {
                       if (!use32BitLanes){
                            for (int i = 0; i < 8; i++){
                                if (registerValueMap.contains(name + reg64BitLaneStrs[i])) {
                                    registerValueMap[name + reg64BitLaneStrs[i]] = std::to_string(registerValue.info.arrays.doubleArray[i]);
                                }
                            }
                            hex.str("");
                            hex.clear();
                            continue;
                        }
                        else{
                            for (int i = 0; i < 16; i++){
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

    const size_t registerCount = std::ranges::count(registerString, ',') + 1;
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
            char c = static_cast<char>(data->EventChar);
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
            char c = static_cast<char>(data->EventChar);

            if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'))
            {
                return 0; // Allow hex characters
            }

            // Allow typing '0' and 'x' for the "0x" prefix
            if (c == '0' || c == 'x' || c == 'X')
            {
                return 0; // Allow '0' or 'x' to form the "0x" prefix
            }

            return 1; // Block any other characters
        }
        return 1; // Block non-ASCII characters
    }

    // This handles continuous editing (runs after text is modified)
    if (data->EventFlag == ImGuiInputTextFlags_CallbackAlways)
    {
        std::string input(data->Buf, data->BufTextLen);

        // If the input starts with "0X" (uppercase), convert it to lowercase "0x"
        if (input.length() >= 2 && input[0] == '0' && input[1] == 'X')
        {
            data->DeleteChars(0, 2);
            data->InsertChars(0, "0x");
            return 1;
        }

        // Ensure characters after "0x" are lowercase hex characters
        if (input.length() > 2)
        {
            bool changed = false;
            for (int i = 2; i < input.length(); ++i)
            {
                char& c = input[i];
                if (c >= 'A' && c <= 'F')
                {
                    c = static_cast<char>(std::tolower(c)); // Convert to lowercase
                    changed = true;
                }
            }

            if (changed)
            {
                // Update the buffer if there were any changes
                data->DeleteChars(0, data->BufTextLen);
                data->InsertChars(0, input.c_str());
                return 1;
            }
        }

        data->BufDirty = true; // Mark buffer as modified
    }

    return 0; // Return 0 to indicate successful handling
}

bool contextShown = false;
contextMenuOption registerContextMenu(){
    contextMenuOption menuOption = NORMAL_ACTION;
    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[RubikRegular16]);
    ImGui::PushStyleColor(ImGuiCol_PopupBg, ImColor(30, 32, 48).Value);
    ImGui::GetStyle().Colors[ImGuiCol_HeaderHovered] = ImColor(0x18, 0x19, 0x26);
    ImGui::PushStyleColor(ImGuiCol_Separator, ImColor(54, 58, 79).Value);
    if (ImGui::BeginPopupContextItem("RegisterContextMenu")) {
        contextShown = true;
        ImGui::PushID("HideRegOpt");

        const std::string actualName = getRegisterActualName(hoveredReg);
        if (ImGui::MenuItem("Hide Register")) {
            if (regInfoMap[actualName].first == 128){
                removeRegisterFromView(hoveredReg);
            }
            else if (regInfoMap[actualName].first == 256){
                removeRegisterFromView(hoveredReg, 2);
            }
            else if (regInfoMap[actualName].first == 512){
                removeRegisterFromView(hoveredReg, 3);
            }
            else{
                auto id = registerValueMap.find(hoveredReg);
                if (id != registerValueMap.end()){
                    registerValueMap.erase(id);
                }
            }
            menuOption = REGISTER_HIDDEN;
        }
        ImGui::PopID();
        ImGui::Separator();
        ImGui::PushID("CopyNameOpt");
        if (ImGui::MenuItem("Copy Register Name")) {
            ImGui::SetClipboardText(hoveredReg.c_str());
        }
        ImGui::PopID();
        ImGui::Separator();
        ImGui::PushID("CopyValueOpt");
        if (ImGui::MenuItem("Copy Register Value")) {
            ImGui::SetClipboardText(registerValueMap[hoveredReg].c_str());
        }
        ImGui::PopID();
        ImGui::Separator();
        ImGui::PushID("ToggleLanesOpt");
        if (ImGui::MenuItem("Toggle Register Lanes", "CTRL+`")) {
            use32BitLanes = !use32BitLanes;
            updateRegistersOnLaneChange();
            menuOption = LANES_TOGGLED;
        }
        ImGui::PopID();
        ImGui::EndPopup();
    }
    ImGui::PopStyleColor(2);
    ImGui::PopFont();
    return menuOption;
}

uint64_t hexStrToInt(const std::string& val){
    const uint64_t ret = std::strtoul(val.c_str(), nullptr, 16);
    return ret;
};

bool isRegisterWithLaneShown(const char* regName, const uint8_t regSize) {
    uint8_t loopTimes = 0;
    const std::vector<std::string> laneStrVec = (use32BitLanes ? reg32BitLaneStrs : reg64BitLaneStrs);

    if (regSize == 128) {
        if (use32BitLanes) {
            loopTimes = 4;
        }
        else {
            loopTimes = 2;
        }
    }
    else if (regSize == 256) {
        if (use32BitLanes) {
            loopTimes = 8;
        }
        else {
            loopTimes = 4;
        }
    }
    else if (regSize == 512) {
        if (use32BitLanes) {
            loopTimes = 16;
        }
        else {
            loopTimes = 8;
        }
    }

    for (auto& i: laneStrVec) {
        if (registerValueMap.contains(getRegisterActualName(regName) + i)) {
            return true;;
        }
    }

    return false;
}

void addRegisterToView(const std::string& reg, const registerValueInfoT& registerInfo) {
    std::string regValue{};
    std::vector<std::string> regValues{};
    bool isRegPresent = false;



    if (regInfoMap[reg].first <= 64){
        regValue= std::to_string(registerInfo.registerValueUn.eightByteVal);
    }
    else if (regInfoMap[reg].first == 128 ){
        for (int i = 0; i < (use32BitLanes ? 4 : 2); i++){
            regValues.push_back(std::to_string(use32BitLanes ? registerInfo.registerValueUn.info.arrays.floatArray[i] : registerInfo.registerValueUn.info.arrays.doubleArray[i]));
        }

        regValue = regValues[0];
    }
    else if (regInfoMap[reg].first == 256) {
        if (use32BitLanes) {
            for (const float i: registerInfo.registerValueUn.info.arrays.floatArray) {
                regValues.push_back(std::to_string(i));
            }
        } else {
            for (const double i: registerInfo.registerValueUn.info.arrays.doubleArray) {
                regValues.push_back(std::to_string(i));
            }
        }

        regValue = regValues[0];
    } else if (regInfoMap[reg].first == 512) {
        if (use32BitLanes){
            for (const float i : registerInfo.registerValueUn.info.arrays.floatArray){
                regValues.push_back(std::to_string(i));
            }
        }
        else{
            for (const double i : registerInfo.registerValueUn.info.arrays.doubleArray){
                regValues.push_back(std::to_string(i));
            }
        }

        regValue = regValues[0];
    }
    else if (regInfoMap[reg].first == 80){
        LOG_ERROR("ST* registers are not supported yet!");
        return;
    }

    LOG_DEBUG("Adding the register " << reg);
     if (regValue == "0"){
    // code for saving register's value
        regValue = "0x00";
    }

    if (registerInfo.registerValueUn.info.is128bit){
        if (!use32BitLanes){
            for (int j = 0; j < 2; j++){
                registerValueMap[reg + reg64BitLaneStrs[j]] = regValues[j];
            }
        }
        else{
            for (int k= 0; k < 4; k++){
                registerValueMap[reg + reg32BitLaneStrs[k]] = regValues[k];
            }
        }
    }
    else if (registerInfo.registerValueUn.info.is256bit){
        if (!use32BitLanes){
            for (int l = 0; l < 4; l++){
                registerValueMap[reg + reg64BitLaneStrs[l]] = regValues[l];
            }
        }
        else{
            for (int m = 0; m < 8; m++){
                registerValueMap[reg + reg32BitLaneStrs[m]] = regValues[m];
            }
        }
    }
    else if (registerInfo.registerValueUn.info.is512bit) {
        if (!use32BitLanes){
            for (int n = 0; n < 8; n++){
                registerValueMap[reg + reg64BitLaneStrs[n]] = regValues[n];
            }
        }
        else{
            for (int c = 0; c < 16; c++){
                registerValueMap[reg + reg32BitLaneStrs[c]] = regValues[c];
            }
        }
    }
    else{
        registerValueMap[reg] = regValue;
    }
}

 void registerCommandsUI() {
    const float footerHeightReserve = ImGui::GetStyle().ItemSpacing.y + ImGui::GetFrameHeightWithSpacing();

    ImGui::BeginChild("ScrollingRegion", ImVec2(0, -footerHeightReserve), false, ImGuiWindowFlags_None);
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
        bool isRegPresent = false;
        auto regs = parseRegisters(registerString);

        for (auto& reg : regs) {
            if (!regInfoMap.contains(toUpperCase(reg))) {
                return;
            }

            auto regInfo = getRegister(reg);
            reg = toUpperCase(reg);

            if (!regInfo.out) {
                continue;
            }

            if (regInfoMap[reg].first > 64){
                isRegPresent = isRegisterWithLaneShown(reg.c_str(), regInfoMap[reg].first);
            }

            if ((!registerValueMap.contains(reg)) && !isRegPresent) {
                addRegisterToView(toUpperCase(reg), regInfo);
            }
            // code for removing the register
            else if (regInfo.registerValueUn.info.is512bit || regInfo.registerValueUn.info.is256bit || regInfo.registerValueUn.info.is128bit) {
                std::string fullRegName{};
                int8_t type = 0;

                if (regInfo.registerValueUn.info.is512bit) {
                    type = 3;
                }
                else if (regInfo.registerValueUn.info.is256bit) {
                    type = 2;
                }
                else if (regInfo.registerValueUn.info.is128bit) {
                    type = 1;
                }

                auto& laneStrVec = (use32BitLanes ? reg32BitLaneStrs : reg64BitLaneStrs);
                int i = 0;
                while (true) {
                    fullRegName = reg + laneStrVec[i];
                    if (registerValueMap.contains(fullRegName)){
                        removeRegisterFromView(reg, type);
                        i++;
                        continue;
                    }

                    ++i;
                    if (i > laneStrVec.size() - 1) {
                        break;
                    }
                }
            }
            else if (registerValueMap.count(reg) != 0){
                registerValueMap.erase(reg);
            }
        }
    }
}

std::string getRegisterActualName(const std::string& regName) {
    if (!(regName.contains('[') && regName.contains(']') && regName.contains(':'))){
        return regName;
    }

    return regName.substr(0, regName.find_first_of('['));
}

uint16_t getRegisterActualSize(std::string str){
    str = getRegisterActualName(str);
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
                            saveUCContext(uc, context);
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
                            saveUCContext(uc, context);
                        }
                    }
                }
            }
            else{
                uc_reg_write(uc, regNameToConstant(regName), &temp);
                saveUCContext(uc, context);
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

            ImGui::PopID();

            ImGui::TableSetColumnIndex(1);

            static char regValueFirst[64] = {};
            strncpy(regValueFirst, regValMapInfo->second.c_str(), sizeof(regValueFirst) - 1);
            regValueFirst[sizeof(regValueFirst) - 1] = '\0';

            ImGui::PushID(index * 2);
            ImGui::SetNextItemWidth(-FLT_MIN);

            bool isBigReg = getRegisterActualSize(regValMapInfo->first) > 64;
            constexpr ImGuiTextFlags flags = ImGuiInputTextFlags_CallbackCharFilter;

            if (registerContextMenu() == REGISTER_HIDDEN) {
                regValMapInfo = registerValueMap.begin();
            }

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
            if (registerContextMenu() == REGISTER_HIDDEN) {
                regValMapInfo = registerValueMap.begin();
            }

            isBigReg = getRegisterActualSize(regValMapInfo->first) > 64;
            int (*callback2)(ImGuiInputTextCallbackData* data) = isBigReg ? decimalCallback: checkHexCharsCallback;

            if (ImGui::InputText(("##regValueSecond" + std::to_string(index)).c_str(), regValueSecond, IM_ARRAYSIZE(regValueSecond), ImGuiInputTextFlags_CharsNoBlank | ImGuiInputTextFlags_EnterReturnsTrue | flags, callback2)) {
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

bool updateRegistersOnLaneChange() {
    for (const auto &regName: registerValueMap | std::views::keys) {
        const auto regSize = getRegisterActualSize(regName);
        if (regSize > 64) {
            int type = 0;

            std::string s1 = regName.substr(regName.find_first_of('[') + 1);
            s1.erase(s1.size() - 1);

            if (regSize == 128) {
                type = 1;
            }
            else if (regSize == 256) {
                type = 2;
            }
            else if (regSize == 512) {
                type = 3;
            }

            use32BitLanes = !use32BitLanes;
            removeRegisterFromView(getRegisterActualName(regName), type);
            use32BitLanes = !use32BitLanes;
            addRegisterToView(getRegisterActualName(regName), getRegister(regName));
        }
    }
    return true;
}