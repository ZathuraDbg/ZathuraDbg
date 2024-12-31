#include "uiElements.h"

using namespace ImGui;
bool InputIntegerPrefix(const char *label, const char *prefix, void *value, ImGuiDataType type, const char *format, ImGuiInputTextFlags flags) {
    auto window             = GetCurrentWindow();
    const ImGuiID id        = window->GetID(label);
    const ImGuiStyle &style = GImGui->Style;

    const ImVec2 label_size = CalcTextSize(label, nullptr, true);
    const ImVec2 frame_size = CalcItemSize(ImVec2(0, 0), CalcTextSize(prefix).x, label_size.y + style.FramePadding.y * 2.0F);
    const ImRect frame_bb(window->DC.CursorPos, window->DC.CursorPos + ImVec2(CalcItemWidth(), frame_size.y));

    SetCursorPosX(GetCursorPosX() + frame_size.x);

    char buf[64];
    uint64_t val = strtoll((char*)value, nullptr, 10);
    std::string hexStr = std::format("{:X}", val);

    strncpy(buf, (char*)hexStr.data(), 64);

    RenderNavCursor(frame_bb, id);
    RenderFrame(frame_bb.Min, frame_bb.Max, GetColorU32(ImGuiCol_FrameBg), true, style.FrameRounding);

    PushStyleVar(ImGuiStyleVar_Alpha, 0.6F);
    RenderText(ImVec2(frame_bb.Min.x + style.FramePadding.x, frame_bb.Min.y + style.FramePadding.y), prefix);
    PopStyleVar();

    bool value_changed = false;
    PushStyleVar(ImGuiStyleVar_FrameBorderSize, 0);
    PushStyleColor(ImGuiCol_FrameBg, 0x00000000);
    PushStyleColor(ImGuiCol_FrameBgHovered, 0x00000000);
    PushStyleColor(ImGuiCol_FrameBgActive, 0x00000000);
    if (InputTextEx(label, nullptr, buf, IM_ARRAYSIZE(buf), ImVec2(CalcItemWidth() - frame_size.x, label_size.y + style.FramePadding.y * 2.0F), flags))
    {
        value_changed = DataTypeApplyFromText(buf, type, value, format);
        strncpy((char*)value, buf, strlen(buf));
    }
    PopStyleColor(3);
    PopStyleVar();

    if (value_changed)
        MarkItemEdited(GImGui->LastItemData.ID);

    return value_changed;
}

bool InputHexadecimal(const char *label, void *value, ImGuiInputTextFlags flags) {
    return InputIntegerPrefix(label, "0x", value, ImGuiDataType_U64, "%llX", flags | ImGuiInputTextFlags_CharsHexadecimal);
}
