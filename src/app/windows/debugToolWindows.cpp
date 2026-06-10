#include "windows.hpp"

#include "../integration/debugState.hpp"

#include <iomanip>
#include <sstream>

namespace {

std::string formatHex(const uint64_t value, const int width = 0) {
    std::ostringstream out;
    out << "0x" << std::hex << std::setfill('0');
    if (width > 0) {
        out << std::setw(width);
    }
    out << value;
    return out.str();
}

std::string addressLineText(const uint64_t address) {
    const auto it = addressLineNoMap.find(address);
    if (it == addressLineNoMap.end() || it->second == 0) {
        return "-";
    }
    return std::to_string(it->second);
}

}

void breakpointManagerWindow() {
    static char newAddress[64] = "";

    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[JetBrainsMono20]);
    ImGui::SetNextItemWidth(180);
    ImGui::InputTextWithHint("##newBreakpointAddress", "0x address", newAddress,
                             IM_ARRAYSIZE(newAddress),
                             ImGuiInputTextFlags_CallbackCharFilter,
                             checkHexCharsCallback);
    ImGui::SameLine();
    if (ImGui::Button("Add")) {
        const auto address = hexStrToInt(newAddress);
        if (address != 0 && debugAddBreakpointAddress(address)) {
            newAddress[0] = '\0';
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear")) {
        while (!breakpointAddresses.empty()) {
            debugRemoveBreakpointAddress(breakpointAddresses.back());
        }
    }

    ImGui::Separator();
    if (ImGui::BeginTable("BreakpointManagerTable", 4,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("No.");
        ImGui::TableSetupColumn("Address");
        ImGui::TableSetupColumn("Line");
        ImGui::TableSetupColumn("Action");
        ImGui::TableHeadersRow();

        for (size_t i = 0; i < breakpointAddresses.size(); ++i) {
            const auto address = breakpointAddresses[i];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("%zu", i + 1);
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(formatHex(address).c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(addressLineText(address).c_str());
            ImGui::TableSetColumnIndex(3);
            ImGui::PushID(static_cast<int>(i));
            if (ImGui::Button("Delete")) {
                debugRemoveBreakpointAddress(address);
                ImGui::PopID();
                break;
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    ImGui::PopFont();
}

void watchpointWindow() {
    static char addressText[64] = "";
    static char sizeText[32] = "1";
    static int kindIndex = 0;
    constexpr const char* kinds[] = {"write", "read", "access"};

    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[JetBrainsMono20]);
    ImGui::SetNextItemWidth(160);
    ImGui::InputTextWithHint("##watchAddress", "0x address", addressText,
                             IM_ARRAYSIZE(addressText),
                             ImGuiInputTextFlags_CallbackCharFilter,
                             checkHexCharsCallback);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(70);
    ImGui::InputTextWithHint("##watchSize", "size", sizeText, IM_ARRAYSIZE(sizeText),
                             ImGuiInputTextFlags_CharsDecimal);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(110);
    ImGui::Combo("##watchKind", &kindIndex, kinds, IM_ARRAYSIZE(kinds));
    ImGui::SameLine();
    if (ImGui::Button("Add")) {
        const auto address = hexStrToInt(addressText);
        const auto size = static_cast<size_t>(std::strtoull(sizeText, nullptr, 10));
        if (addDebugWatchpoint(address, size, static_cast<WatchpointKind>(kindIndex))) {
            addressText[0] = '\0';
            std::snprintf(sizeText, sizeof(sizeText), "1");
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear")) {
        clearDebugWatchpoints();
    }

    ImGui::Separator();
    auto& watchpoints = mutableDebugWatchpoints();
    if (ImGui::BeginTable("WatchpointsTable", 6,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("No.");
        ImGui::TableSetupColumn("Kind");
        ImGui::TableSetupColumn("Address");
        ImGui::TableSetupColumn("Size");
        ImGui::TableSetupColumn("Hits");
        ImGui::TableSetupColumn("Action");
        ImGui::TableHeadersRow();

        for (size_t i = 0; i < watchpoints.size(); ++i) {
            auto& watchpoint = watchpoints[i];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("%zu", i + 1);
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(watchpointKindName(watchpoint.kind));
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(formatHex(watchpoint.address).c_str());
            ImGui::TableSetColumnIndex(3);
            ImGui::Text("%zu", watchpoint.size);
            ImGui::TableSetColumnIndex(4);
            if (watchpoint.hitCount > 0) {
                ImGui::Text("%llu %s %s",
                            static_cast<unsigned long long>(watchpoint.hitCount),
                            watchpoint.lastAccess.c_str(),
                            formatHex(watchpoint.lastHitAddress).c_str());
            } else {
                ImGui::TextUnformatted("-");
            }
            ImGui::TableSetColumnIndex(5);
            ImGui::PushID(static_cast<int>(i));
            if (ImGui::Button("Delete")) {
                removeDebugWatchpoint(i);
                ImGui::PopID();
                break;
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    ImGui::PopFont();
}

void stateChangesWindow() {
    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[JetBrainsMono20]);
    if (ImGui::Button("Clear")) {
        clearDebugDiffs();
    }

    ImGui::SeparatorText("Registers");
    if (ImGui::BeginTable("RegisterDiffTable", 3,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Register");
        ImGui::TableSetupColumn("Before");
        ImGui::TableSetupColumn("After");
        ImGui::TableHeadersRow();
        for (const auto& change : debugRegisterChanges()) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TextUnformatted(toUpperCase(change.name).c_str());
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(change.before.c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(change.after.c_str());
        }
        ImGui::EndTable();
    }

    ImGui::SeparatorText("Memory");
    if (ImGui::BeginTable("MemoryDiffTable", 3,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Address");
        ImGui::TableSetupColumn("Before");
        ImGui::TableSetupColumn("After");
        ImGui::TableHeadersRow();
        for (const auto& change : debugMemoryChanges()) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TextUnformatted(formatHex(change.address).c_str());
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(formatHex(change.before, 2).c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(formatHex(change.after, 2).c_str());
        }
        ImGui::EndTable();
    }

    ImGui::SeparatorText("Stack");
    if (ImGui::BeginTable("StackDiffTable", 3,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Address");
        ImGui::TableSetupColumn("Before");
        ImGui::TableSetupColumn("After");
        ImGui::TableHeadersRow();
        for (const auto& change : debugStackMemoryChanges()) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TextUnformatted(formatHex(change.address).c_str());
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(formatHex(change.before, 2).c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(formatHex(change.after, 2).c_str());
        }
        ImGui::EndTable();
    }
    ImGui::PopFont();
}
