// Mini memory editor for Dear ImGui (to embed in your game/tools)
// Get latest version at http://www.github.com/ocornut/imgui_club
//
// Right-click anywhere to access the Options menu!
// You can adjust the keyboard repeat delay/rate in ImGuiIO.
// The code assume a mono-space font for simplicity!
// If you don't use the default font, use ImGui::PushFont()/PopFont() to switch to a mono-space font before calling this.
//
// Usage:
//   // Create a window and draw memory editor inside it:
//   static MemoryEditor mem_edit_1;
//   static char data[0x10000];
//   size_t data_size = 0x10000;
//   mem_edit_1.DrawWindow("Memory Editor", data, data_size);
//
// Usage:
//   // If you already have a window, use DrawContents() instead:
//   static MemoryEditor mem_edit_2;
//   ImGui::Begin("MyWindow")
//   mem_edit_2.DrawContents(this, sizeof(*this), (size_t)this);
//   ImGui::End();
//
// Changelog:
// - v0.10: initial version
// - v0.23 (2017/08/17): added to github. fixed right-arrow triggering a byte write.
// - v0.24 (2018/06/02): changed DragInt("Rows" to use a %d data format (which is desirable since imgui 1.61).
// - v0.25 (2018/07/11): fixed wording: all occurrences of "Rows" renamed to "Columns".
// - v0.26 (2018/08/02): fixed clicking on hex region
// - v0.30 (2018/08/02): added data preview for common data types
// - v0.31 (2018/10/10): added OptUpperCaseHex option to select lower/upper casing display [@samhocevar]
// - v0.32 (2018/10/10): changed signatures to use void* instead of unsigned char*
// - v0.33 (2018/10/10): added OptShowOptions option to hide all the interactive option setting.
// - v0.34 (2019/05/07): binary preview now applies endianness setting [@nicolasnoble]
// - v0.35 (2020/01/29): using ImGuiDataType available since Dear ImGui 1.69.
// - v0.36 (2020/05/05): minor tweaks, minor refactor.
// - v0.40 (2020/10/04): fix misuse of ImGuiListClipper API, broke with Dear ImGui 1.79. made cursor position appears on left-side of edit box. option popup appears on mouse release. fix MSVC warnings where _CRT_SECURE_NO_WARNINGS wasn't working in recent versions.
// - v0.41 (2020/10/05): fix when using with keyboard/gamepad navigation enabled.
// - v0.42 (2020/10/14): fix for . character in ASCII view always being greyed out.
// - v0.43 (2021/03/12): added OptFooterExtraHeight to allow for custom drawing at the bottom of the editor [@leiradel]
// - v0.44 (2021/03/12): use ImGuiInputTextFlags_AlwaysOverwrite in 1.82 + fix hardcoded width.
// - v0.50 (2021/11/12): various fixes for recent dear imgui versions (fixed misuse of clipper, relying on SetKeyboardFocusHere() handling scrolling from 1.85). added default size.
// - v0.51 (2024/02/22): fix for layout change in 1.89 when using IMGUI_DISABLE_OBSOLETE_FUNCTIONS. (#34)
// - v0.52 (2024/03/08): removed unnecessary GetKeyIndex() calls, they are a no-op since 1.87.
//
// Todo/Bugs:
// - This is generally old/crappy code, it should work but isn't very good.. to be rewritten some day.
// - PageUp/PageDown are not supported because we use _NoNav. This is a good test scenario for working out idioms of how to mix natural nav and our own...
// - Arrows are being sent to the InputText() about to disappear which for LeftArrow makes the text cursor appear at position 1 for one frame.
// - Using InputText() is awkward and maybe overkill here, consider implementing something custom.

#pragma once

#include <cstdio>      // sprintf, scanf
#include <cstdint>     // uint8_t, etc.
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <stack>
#include <variant>

#include "../../src/utils/iconfont.h"
#include "../../src/utils/fonts.hpp"
#ifdef _MSC_VER
#define _PRISizeT   "I"
#define ImSnprintf  _snprintf
#else
#define _PRISizeT   "z"
#define ImSnprintf  snprintf
#endif

#ifdef _MSC_VER
#pragma warning (push)
#pragma warning (disable: 4996) // warning C4996: 'sprintf': This function or variable may be unsafe.
#endif

struct MemoryEditor
{
    enum DataFormat
    {
        DataFormat_Bin = 0,
        DataFormat_Dec = 1,
        DataFormat_Hex = 2,
        DataFormat_COUNT
    };

    enum ActionType{
        MemWrite,
        MemWriteBatch,
        SetBaseAddr
    };

    struct Actions{
        ActionType Action;
        uint64_t startAddr;
        uint64_t endAddr;
        size_t operationSize;
        std::vector<intptr_t> operationData;
        std::vector<intptr_t> originalData;
    };

    struct fillRangeInfoT{
        uint64_t address;
        int size;
        char character;
    };

    // Settings
    bool            Open;                                       // = true   // set to false when DrawWindow() was closed. ignore if not using DrawWindow().
    bool            ReadOnly;                                   // = false  // disable any editing.
    int             Cols;                                       // = 16     // number of columns to display.
    bool            OptShowOptions;                             // = true   // display options button/context menu. when disabled, options will be locked unless you provide your own UI for them.
    bool            OptShowDataPreview;                         // = false  // display a footer previewing the decimal/binary/hex/float representation of the currently selected bytes.
    bool            OptShowHexII;                               // = false  // display values in HexII representation instead of regular hexadecimal: hide null/zero bytes, ascii values as ".X".
    bool            OptShowAscii;                               // = true   // display ASCII representation on the right side.
    bool            OptGreyOutZeroes;                           // = true   // display null/zero bytes using the TextDisabled color.
    bool            OptUpperCaseHex;                            // = true   // display hexadecimal values as "FF" instead of "ff".
    bool            OptShowAddWindowButton;                     // = false  // display a "+" to add a new window
    int             OptMidColsCount;                            // = 8      // set to 0 to disable extra spacing between every mid-cols.
    int             OptAddrDigitsCount;                         // = 0      // number of addr digits to display (default calculated based on maximum displayed addr).
    bool            OptShowSetBaseAddrOption;                   // = false  // show the option to set the update the base address of the window
    bool            OptFillMemoryRange;                         // = false  // allows you to have a function which can fill memory ranges
    float           OptFooterExtraHeight;                       // = 0      // space to reserve at the bottom of the widget to add custom widgets
    ImU32           HighlightColor;                             //          // background color of highlighted bytes.
    ImU32 (*BgColorFn)(const ImU8* data, size_t off);
    void (*InteractFn)(const ImU8* data, size_t off);
    void            GoToPopup();
    ImU8            (*ReadFn)(const ImU8* data, size_t off);    // = 0      // optional handler to read bytes.
    void            (*WriteFn)(ImU8* data, size_t off, ImU8 d); // = 0      // optional handler to write bytes.
    bool            (*HighlightFn)(const ImU8* data, size_t off);//= 0      // optional handler to return Highlight property (to support non-contiguous highlighting).
    bool            (*NewWindowInfoFn)();
    bool            (*ShowRequiredButton)(const std::string& buttonName, bool state);
    fillRangeInfoT  (*FillMemoryRange)();
    std::variant<bool, std::pair<void*, size_t>> (*SetBaseAddress2)(uintptr_t baseAddr, uintptr_t size);

    // [Internal State]
    bool            ContentsWidthChanged;
    size_t          DataPreviewAddr;
    size_t          DataEditingAddr;
    size_t          SelectionStartAddr;
    size_t          SelectionEndAddr;
    size_t          HoveredAddr;
    uint64_t        BaseDisplayAddr;
    bool            DataEditingTakeFocus;
    char            DataInputBuf[32];
    char            AddrInputBuf[32];
    size_t          GotoAddr;
    size_t          HighlightMin, HighlightMax;
    int             PreviewEndianness;
    ImGuiDataType   PreviewDataType;
    bool            Keep;
    bool            KeepSetBaseAddrWindow;
    bool            KeepFillMemoryWindow;
    bool            KeepGoToPopup;
    bool            CopySelection;
    bool            StackFashionAddrSubtraction;
    uint8_t*        MemData;
    std::stack<Actions> UndoActions;
    std::stack<Actions> RedoActions;

    MemoryEditor()
    {
        // Settings
        Open = true;
        ReadOnly = false;
        Cols = 16;
        OptShowOptions = true;
        OptShowDataPreview = false;
        OptShowHexII = false;
        OptShowAscii = true;
        OptGreyOutZeroes = true;
        OptUpperCaseHex = true;
        OptMidColsCount = 8;
        OptAddrDigitsCount = 0;
        OptFooterExtraHeight = 0.0f;
        HighlightColor = IM_COL32(0, 0, 0, 0);
        SelectionEndAddr = SelectionStartAddr = -1;
        ReadFn = nullptr;
        WriteFn = nullptr;
        HighlightFn = nullptr;
        BgColorFn = nullptr;
        InteractFn = nullptr;
        ShowRequiredButton = nullptr;
        Keep = false;
        // State/Internals
        ContentsWidthChanged = false;
        DataPreviewAddr = DataEditingAddr = (size_t)-1;
        DataEditingTakeFocus = false;
        memset(DataInputBuf, 0, sizeof(DataInputBuf));
        memset(AddrInputBuf, 0, sizeof(AddrInputBuf));
        GotoAddr = (size_t)-1;
        HighlightMin = HighlightMax = (size_t)-1;
        PreviewEndianness = 0;
        PreviewDataType = ImGuiDataType_S32;
        NewWindowInfoFn = nullptr;
        MemData = nullptr;
        UndoActions = {};
        RedoActions = {};
    }

    void GotoAddrAndHighlight(size_t addr_min, size_t addr_max)
    {
        GotoAddr = addr_min;
        HighlightMin = addr_min;
        HighlightMax = addr_max;
    }


    struct Sizes
    {
        int     AddrDigitsCount;
        float   LineHeight;
        float   GlyphWidth;
        float   HexCellWidth;
        float   SpacingBetweenMidCols;
        float   PosHexStart;
        float   PosHexEnd;
        float   PosAsciiStart;
        float   PosAsciiEnd;
        float   WindowWidth;

        Sizes() { memset(this, 0, sizeof(*this)); }
    };



    void CalcSizes(Sizes& s, size_t mem_size, size_t base_display_addr)
    {
        ImGuiStyle& style = ImGui::GetStyle();
        s.AddrDigitsCount = OptAddrDigitsCount;
        if (s.AddrDigitsCount == 0)
            for (size_t n = base_display_addr + mem_size - 1; n > 0; n >>= 4)
                s.AddrDigitsCount++;
        s.LineHeight = ImGui::GetTextLineHeight();
        s.GlyphWidth = ImGui::CalcTextSize("F").x + 1;                  // We assume the font is mono-space
        s.HexCellWidth = (float)(int)(s.GlyphWidth * 2.5f);             // "FF " we include trailing space in the width to easily catch clicks everywhere
        s.SpacingBetweenMidCols = (float)(int)(s.HexCellWidth * 0.25f); // Every OptMidColsCount columns we add a bit of extra spacing
        s.PosHexStart = (s.AddrDigitsCount + 2) * s.GlyphWidth;
        s.PosHexEnd = s.PosHexStart + (s.HexCellWidth * Cols);
        s.PosAsciiStart = s.PosAsciiEnd = s.PosHexEnd;
        if (OptShowAscii)
        {
            s.PosAsciiStart = s.PosHexEnd + s.GlyphWidth * 1;
            if (OptMidColsCount > 0)
                s.PosAsciiStart += (float)((Cols + OptMidColsCount - 1) / OptMidColsCount) * s.SpacingBetweenMidCols;
            s.PosAsciiEnd = s.PosAsciiStart + Cols * s.GlyphWidth;
        }
        s.WindowWidth = s.PosAsciiEnd + style.ScrollbarSize + style.WindowPadding.x * 2 + s.GlyphWidth;
    }

    // Standalone Memory Editor window
    void DrawWindow(const char* title, void* mem_data, size_t mem_size, size_t base_display_addr = 0x0000)
    {
        Sizes s;
        CalcSizes(s, mem_size, base_display_addr);
        ImGui::SetNextWindowSize(ImVec2(s.WindowWidth, s.WindowWidth * 0.60f), ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowSizeConstraints(ImVec2(0.0f, 0.0f), ImVec2(s.WindowWidth, FLT_MAX));
        BaseDisplayAddr = base_display_addr;
        Open = true;
        if (ImGui::Begin(title, &Open, ImGuiWindowFlags_NoScrollbar))
        {
            // Create a context menu ID unique to this window
            char contextMenuName[256];
            ImSnprintf(contextMenuName, sizeof(contextMenuName), "%s_context", title);
            
            // Right-click anywhere in window will open the context menu
            if (ImGui::IsWindowHovered(ImGuiHoveredFlags_RootAndChildWindows) && ImGui::IsMouseReleased(ImGuiMouseButton_Right))
                ImGui::OpenPopup(contextMenuName);
            
            DrawContents(mem_data, mem_size, base_display_addr, contextMenuName);
            if (ContentsWidthChanged)
            {
                CalcSizes(s, mem_size, base_display_addr);
                ImGui::SetWindowSize(ImVec2(s.WindowWidth, ImGui::GetWindowSize().y));
            }
        }
        ImGui::End();
    }

    std::string ReadMemory(uint64_t startAddr, uint64_t endAddr){
        if (startAddr > endAddr){
            std::swap(startAddr, endAddr);
        }

        uint64_t blockSize = (endAddr - startAddr) + 1;

        auto *buffer = (unsigned char*)malloc(blockSize);
        memcpy(buffer, MemData + startAddr, blockSize);
        std::stringstream ss;
        ss << std::hex << std::uppercase << std::setfill('0');
        for (size_t i = 0; i < blockSize; ++i) {
            ss << std::setw(2) << static_cast<int>(buffer[i]) << " ";
        }
        std::string res = ss.str();
        if (res.ends_with(' ')){
            res.pop_back();
        }
        return res;
    }

    // Memory Editor contents only
    void DrawContents(void* mem_data_void, size_t mem_size, size_t base_display_addr = 0x0000, const char* contextMenuName = "context") {
        if (Cols < 1)
            Cols = 1;

        static bool KeepNewWindowInfoFn;
        ImU8* mem_data = (ImU8*)mem_data_void;
        MemData = static_cast<uint8_t *>(mem_data_void);
        Sizes s;
        CalcSizes(s, mem_size, base_display_addr);
        ImGuiStyle& style = ImGui::GetStyle();

        // We begin into our scrolling region with the 'ImGuiWindowFlags_NoMove' in order to prevent click from moving the window.
        // This is used as a facility since our main click detection code doesn't assign an ActiveId so the click would normally be caught as a window-move.
        const float height_separator = style.ItemSpacing.y;
        float footer_height = OptFooterExtraHeight;
        if (OptShowOptions)
            footer_height += height_separator + ImGui::GetFrameHeightWithSpacing() * 1;
        if (OptShowDataPreview)
            footer_height += height_separator + ImGui::GetFrameHeightWithSpacing() * 1 + ImGui::GetTextLineHeightWithSpacing() * 3;
        ImGui::BeginChild("##scrolling", ImVec2(0, -footer_height), false, ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoNav);
        ImDrawList* draw_list = ImGui::GetWindowDrawList();

        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 0));
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 0));

        // We are not really using the clipper API correctly here, because we rely on visible_start_addr/visible_end_addr for our scrolling function.
        const int line_total_count = (int)((mem_size + Cols - 1) / Cols);
        ImGuiListClipper clipper;
        clipper.Begin(line_total_count, s.LineHeight);

        bool data_next = false;

        if (ReadOnly || DataEditingAddr >= mem_size)
            DataEditingAddr = (size_t)-1;
        if (DataPreviewAddr >= mem_size)
            DataPreviewAddr = (size_t)-1;

        size_t preview_data_type_size = OptShowDataPreview ? DataTypeGetSize(PreviewDataType) : 0;

        size_t data_editing_addr_next = (size_t)-1;
        if (DataEditingAddr != (size_t)-1)
        {
            // Move cursor but only apply on next frame so scrolling with be synchronized (because currently we can't change the scrolling while the window is being rendered)
            if (ImGui::IsKeyPressed(ImGuiKey_UpArrow) && (ptrdiff_t)DataEditingAddr >= (ptrdiff_t)Cols)                 { data_editing_addr_next = DataEditingAddr - Cols; }
            else if (ImGui::IsKeyPressed(ImGuiKey_DownArrow) && (ptrdiff_t)DataEditingAddr < (ptrdiff_t)mem_size - Cols){ data_editing_addr_next = DataEditingAddr + Cols; }
            else if (ImGui::IsKeyPressed(ImGuiKey_LeftArrow) && (ptrdiff_t)DataEditingAddr > (ptrdiff_t)0)              { data_editing_addr_next = DataEditingAddr - 1; }
            else if (ImGui::IsKeyPressed(ImGuiKey_RightArrow) && (ptrdiff_t)DataEditingAddr < (ptrdiff_t)mem_size - 1)  { data_editing_addr_next = DataEditingAddr + 1; }
        }

        // Draw vertical separator
        ImVec2 window_pos = ImGui::GetWindowPos();
        if (OptShowAscii)
            draw_list->AddLine(ImVec2(window_pos.x + s.PosAsciiStart - s.GlyphWidth, window_pos.y), ImVec2(window_pos.x + s.PosAsciiStart - s.GlyphWidth, window_pos.y + 9999), ImGui::GetColorU32(ImGuiCol_Border));

        const ImU32 color_text = ImGui::GetColorU32(ImGuiCol_Text);
        const ImU32 color_disabled = OptGreyOutZeroes ? ImGui::GetColorU32(ImGuiCol_TextDisabled) : color_text;

        const char* format_address = OptUpperCaseHex ? "%0*" _PRISizeT "X: " : "%0*" _PRISizeT "x: ";
        const char* format_data = OptUpperCaseHex ? "%0*" _PRISizeT "X" : "%0*" _PRISizeT "x";
        const char* format_byte = OptUpperCaseHex ? "%02X" : "%02x";
        const char* format_byte_space = OptUpperCaseHex ? "%02X " : "%02x ";

        // Disallow interacting with multiple bytes simultaneously.
        // This is needed because consecutive hex cells overlap each other by 1 pixel.
        bool interact_invoked = false;

        while (clipper.Step())
            for (int line_i = clipper.DisplayStart; line_i < clipper.DisplayEnd; line_i++) // display only visible lines
            {
                size_t addr = (size_t)(line_i * Cols);
                if (StackFashionAddrSubtraction) {
                    ImGui::Text(format_address, s.AddrDigitsCount, base_display_addr - addr);
                }
                else {
                    ImGui::Text(format_address, s.AddrDigitsCount, (base_display_addr + addr));
                }
                // Draw Hexadecimal
                for (int n = 0; n < Cols && addr < mem_size; n++, addr++)
                {
                    float byte_pos_x = s.PosHexStart + s.HexCellWidth * n;
                    if (OptMidColsCount > 0)
                        byte_pos_x += (float)(n / OptMidColsCount) * s.SpacingBetweenMidCols;
                    ImGui::SameLine(byte_pos_x);

                    // Draw highlight
                    bool is_highlight_from_user_range = (addr >= HighlightMin && addr < HighlightMax);
                    bool is_highlight_from_user_func = (HighlightFn && HighlightFn(mem_data, addr));
                    bool is_highlight_from_preview = (addr >= DataPreviewAddr && addr < DataPreviewAddr + preview_data_type_size);
                    bool is_selection_highlight = false;
                    if (((SelectionStartAddr != -1))){
                        if ((addr <= SelectionEndAddr && addr >= SelectionStartAddr) || ((addr >= SelectionEndAddr && addr <= SelectionStartAddr) && (SelectionStartAddr > SelectionEndAddr))){
                            is_selection_highlight = true;
                        }
                    };
                    if (is_highlight_from_user_range || is_highlight_from_user_func || is_highlight_from_preview || is_selection_highlight)
                    {
                        ImVec2 pos = ImGui::GetCursorScreenPos();
                        float highlight_width = s.GlyphWidth * 2;
                        bool is_next_byte_highlighted = (addr + 1 < mem_size) && ((HighlightMax != (size_t)-1 && addr + 1 < HighlightMax) || (HighlightFn && HighlightFn(mem_data, addr + 1)));
                        if (is_next_byte_highlighted || (n + 1 == Cols))
                        {
                            highlight_width = s.HexCellWidth;
                            if (OptMidColsCount > 0 && n > 0 && (n + 1) < Cols && ((n + 1) % OptMidColsCount) == 0)
                                highlight_width += s.SpacingBetweenMidCols;
                        }
                        draw_list->AddRectFilled(pos, ImVec2(pos.x + highlight_width, pos.y + s.LineHeight), HighlightColor);
                    }
                    else if (BgColorFn)
                    {
                        ImVec2 pos = ImGui::GetCursorScreenPos();
                        float highlight_width = s.GlyphWidth * 2;
                        bool is_next_byte_highlighted = (addr + 1 < mem_size) && ((BgColorFn(mem_data, addr + 1) & IM_COL32_A_MASK) != 0);
                        if (is_next_byte_highlighted || (n + 1 == Cols))
                        {
                            highlight_width = s.HexCellWidth;
                            if (OptMidColsCount > 0 && n > 0 && (n + 1) < Cols && ((n + 1) % OptMidColsCount) == 0)
                                highlight_width += s.SpacingBetweenMidCols;
                        }
                        draw_list->AddRectFilled(pos, ImVec2(pos.x + highlight_width, pos.y + s.LineHeight), BgColorFn(mem_data, addr));
                    }

                    if (DataEditingAddr == addr)
                    {
                        // Display text input on current byte
                        bool data_write = false;
                        ImGui::PushID((void*)addr);
                        if (DataEditingTakeFocus)
                        {
                            ImGui::SetKeyboardFocusHere(0);
                            sprintf(AddrInputBuf, format_data, s.AddrDigitsCount, base_display_addr + addr);
                            sprintf(DataInputBuf, format_byte, ReadFn ? ReadFn(mem_data, addr) : mem_data[addr]);
                            ImGui::SetNextItemWidth(s.GlyphWidth * 2);
                        }
                        struct UserData
                        {
                            // FIXME: We should have a way to retrieve the text edit cursor position more easily in the API, this is rather tedious. This is such a ugly mess we may be better off not using InputText() at all here.
                            static int Callback(ImGuiInputTextCallbackData* data)
                            {
                                UserData* user_data = (UserData*)data->UserData;
                                if (!data->HasSelection())
                                    user_data->CursorPos = data->CursorPos;
                                if (data->SelectionStart == 0 && data->SelectionEnd == data->BufTextLen)
                                {
                                    // When not editing a byte, always refresh its InputText content pulled from underlying memory data
                                    // (this is a bit tricky, since InputText technically "owns" the master copy of the buffer we edit it in there)
                                    data->DeleteChars(0, data->BufTextLen);
                                    data->InsertChars(0, user_data->CurrentBufOverwrite);
                                    data->SelectionStart = 0;
                                    data->SelectionEnd = 2;
                                    data->CursorPos = 0;
                                }
                                return 0;
                            }
                            char   CurrentBufOverwrite[3];  // Input
                            int    CursorPos;               // Output
                        };
                        UserData user_data;
                        user_data.CursorPos = -1;
                        sprintf(user_data.CurrentBufOverwrite, format_byte, ReadFn ? ReadFn(mem_data, addr) : mem_data[addr]);

                        if ((ImGui::IsKeyDown(ImGuiKey_LeftShift))){
                            if (SelectionStartAddr == -1){
                                SelectionStartAddr = addr;
                                SelectionEndAddr = addr;
                            }

                            SelectionEndAddr = addr;
                        }
                        else if (SelectionStartAddr != -1 && (addr != SelectionEndAddr)){
                            SelectionStartAddr = -1;
                        }
                        ImGuiInputTextFlags flags = ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll | ImGuiInputTextFlags_NoHorizontalScroll | ImGuiInputTextFlags_CallbackAlways;
                        flags |= ImGuiInputTextFlags_AlwaysOverwrite; // was ImGuiInputTextFlags_AlwaysInsertMode
                        ImGui::SetNextItemWidth(s.GlyphWidth * 2);
                        if (ImGui::InputText("##data", DataInputBuf, IM_ARRAYSIZE(DataInputBuf), flags, UserData::Callback, &user_data))
                            data_write = data_next = true;
                        else if (!DataEditingTakeFocus && !ImGui::IsItemActive())
                            DataEditingAddr = data_editing_addr_next = (size_t)-1;
                        DataEditingTakeFocus = false;
                        if (user_data.CursorPos >= 2)
                            data_write = data_next = true;
                        if (data_editing_addr_next != (size_t)-1)
                            data_write = data_next = false;
                        unsigned int data_input_value = 0;
                        if (data_write && sscanf(DataInputBuf, "%X", &data_input_value) == 1)
                        {
                            if (WriteFn){
                                WriteFn(mem_data, addr, (ImU8)data_input_value);
                                Actions undoAction = {.Action = MemWrite, .startAddr = addr, .endAddr = addr + 1, .operationSize = 1};
                                undoAction.operationData.push_back(data_input_value);
                                undoAction.originalData.push_back(mem_data[addr]);
                                UndoActions.push(undoAction);
                            }
                            else
                                mem_data[addr] = (ImU8)data_input_value;
                        }
                        ImGui::PopID();
                    }
                    else
                    {
                        // NB: The trailing space is not visible but ensure there's no gap that the mouse cannot click on.
                        ImU8 b = ReadFn ? ReadFn(mem_data, addr) : mem_data[addr];

                        if (OptShowHexII)
                        {
                            if ((b >= 32 && b < 128))
                                ImGui::Text(".%c ", b);
                            else if (b == 0xFF && OptGreyOutZeroes)
                                ImGui::TextDisabled("## ");
                            else if (b == 0x00)
                                ImGui::Text("   ");
                            else
                                ImGui::Text(format_byte_space, b);
                        }
                        else
                        {
                            if (b == 0 && OptGreyOutZeroes)
                                ImGui::TextDisabled("00 ");
                            else
                                ImGui::Text(format_byte_space, b);
                        }
                        if (!ReadOnly && ImGui::IsItemHovered() && ImGui::IsMouseClicked(0))
                        {
                            DataEditingTakeFocus = true;
                            data_editing_addr_next = addr;
                        }
                        else if (InteractFn && ImGui::IsItemHovered()) {
                            if (!interact_invoked) {
                                // Revert padding/spacing to let users draw popups/windows without interference
                                ImGui::PopStyleVar(2);
                                InteractFn(mem_data, addr);
                                interact_invoked = true;
                                ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 0));
                                ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 0));
                            }


                        }
                        if (ImGui::IsItemHovered()){
                            HoveredAddr = addr;
                        }
                    }
                }

                if (OptShowAscii)
                {
                    // Draw ASCII values
                    ImGui::SameLine(s.PosAsciiStart);
                    ImVec2 pos = ImGui::GetCursorScreenPos();
                    addr = line_i * Cols;
                    size_t mouseAddr = addr + (size_t)((ImGui::GetIO().MousePos.x - pos.x) / s.GlyphWidth);
                    ImGui::PushID(line_i);
                    if (ImGui::InvisibleButton("ascii", ImVec2(s.PosAsciiEnd - s.PosAsciiStart, s.LineHeight)))
                    {
                        DataEditingAddr = DataPreviewAddr = addr + (size_t)((ImGui::GetIO().MousePos.x - pos.x) / s.GlyphWidth);
                        DataEditingTakeFocus = true;
                    }
                    if (InteractFn && ImGui::IsItemHovered())
                    {
                        if (!interact_invoked)
                        {
                            // Revert padding/spacing to let users draw popups/windows without interference
                            ImGui::PopStyleVar(2);
                            InteractFn(mem_data, mouseAddr);
                            interact_invoked = true;
                            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 0));
                            ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 0));
                        }
                    }
                    ImGui::PopID();
                    for (int n = 0; n < Cols && addr < mem_size; n++, addr++)
                    {
                        if (addr == DataEditingAddr)
                        {
                            draw_list->AddRectFilled(pos, ImVec2(pos.x + s.GlyphWidth, pos.y + s.LineHeight), ImColor(59, 60, 79));
                        }
                        else if (BgColorFn)
                        {
                            draw_list->AddRectFilled(pos, ImVec2(pos.x + s.GlyphWidth, pos.y + s.LineHeight), BgColorFn(mem_data, addr));
                        }
                        unsigned char c = ReadFn ? ReadFn(mem_data, addr) : mem_data[addr];
                        char display_c = (c < 32 || c >= 128) ? '.' : c;
                        draw_list->AddText(pos, (display_c == c) ? color_text : color_disabled, &display_c, &display_c + 1);
                        pos.x += s.GlyphWidth;
                    }
                }
            }
        ImGui::PopStyleVar(2);
        ImGui::EndChild();

        // Notify the main window of our ideal child content size (FIXME: we are missing an API to get the contents size from the child)
        ImGui::SetCursorPosX(s.WindowWidth);
        ImGui::Dummy(ImVec2(0.0f, 0.0f));

        if (data_next && DataEditingAddr + 1 < mem_size)
        {
            DataEditingAddr = DataPreviewAddr = DataEditingAddr + 1;
            DataEditingTakeFocus = true;
        }
        else if (data_editing_addr_next != (size_t)-1)
        {
            DataEditingAddr = DataPreviewAddr = data_editing_addr_next;
            DataEditingTakeFocus = true;
        }

        const bool lock_show_data_preview = OptShowDataPreview;
        if (OptShowOptions)
        {
            ImGui::Separator();
            DrawOptionsLine(s, mem_data, mem_size, base_display_addr, contextMenuName);
        }

        if (lock_show_data_preview)
        {
            ImGui::Separator();
            DrawPreviewLine(s, mem_data, mem_size, base_display_addr);
        }


        if (OptShowAddWindowButton){
            ImGui::SameLine();
            ImGui::SetCursorPosX(ImGui::GetWindowSize().x - 30);
            if (ImGui::Button("+")){
                if (NewWindowInfoFn != nullptr) {
                    KeepNewWindowInfoFn = true;
                }
            }
        }

        if (KeepFillMemoryWindow && FillMemoryRange){
            auto [address, upto, character] = FillMemoryRange();
            if ((address == 0 && upto == 1 && character == -1)){
                // cancel
                KeepFillMemoryWindow = false;
            }
            else if (!(address == 0 && upto == 0 && character <= 0)){
                FillRangeWithByte(address, upto, character);
                KeepFillMemoryWindow = false;
            }
        }


        if (KeepNewWindowInfoFn && NewWindowInfoFn){
            if (NewWindowInfoFn()){
                KeepNewWindowInfoFn = false;
            }
        }

        if (KeepSetBaseAddrWindow && SetBaseAddress2){
            auto val = SetBaseAddress2(0, 0);
            if (std::holds_alternative<std::pair<void*, size_t>>(val)) {
                auto const&[addr, size] = std::get<std::pair<void*, size_t>>(val);
                if (addr != mem_data_void) {
                    Actions changeAddrAction = {.Action = ActionType::SetBaseAddr, .startAddr = reinterpret_cast<uintptr_t>(addr), .endAddr = (uintptr_t)(reinterpret_cast<uintptr_t>(addr) + size),.operationSize = size,
                    .operationData = {reinterpret_cast<intptr_t>(addr)}, .originalData = {static_cast<intptr_t>(base_display_addr)}};
                    UndoActions.push(changeAddrAction);
                    KeepSetBaseAddrWindow = false;
                }
            }
            else if (std::holds_alternative<bool>(val)){
                if ( std::get<bool>(val)){
                    KeepSetBaseAddrWindow = false;
                }
            }
        }

        if (KeepGoToPopup) {
            GoToPopup();
        }

        /* Note: We don't have keyboard shortcuts for goto, fill memory with byte and select all
         * because somehow the data between the two instances of the hex editor, which are
         * that of the memory editor and that of the stack editor are getting mixed and that is causing
         * them to not work at all.
         * I expected this to be fixed later, but at the moment I have no idea what to do with this.
         * I have tried using the same callback function with different IDs when they are called from
         * stack and the memory editor, but it doesn't seem to work.
        */

        if (ImGui::IsKeyDown(ImGuiKey_LeftCtrl) && ImGui::IsKeyPressed(ImGuiKey_Z)){
            UndoRedo();
        }

        if (ImGui::IsKeyDown(ImGuiKey_LeftCtrl) && ImGui::IsKeyPressed(ImGuiKey_Y)){
            UndoRedo(true);
        }

        if (ImGui::IsKeyDown(ImGuiKey_LeftCtrl) && ImGui::IsKeyDown(ImGuiKey_LeftShift) && ImGui::IsKeyDown(ImGuiKey_E)){
            KeepSetBaseAddrWindow = true;
        }
    }

    std::string GetDataToCopy(std::string bytes, bool asArray) {
        std::string dataToCopy = asArray ? "{0x" : "\\x";
        
        if (asArray){
            if (!bytes.empty()) {
                for (size_t i = 0; i < bytes.length(); i++) {
                    if (bytes[i]!=' '){
                        dataToCopy += bytes[i];
                    }
                    else{
                        dataToCopy += ", 0x";
                    }
                }

                dataToCopy.append("}");
            }
        }
        else{
            for (size_t i = 0; i < bytes.length(); i++){
                if (bytes[i] != ' '){
                    dataToCopy += bytes[i];
                }
                else{
                    dataToCopy += "\\x";
                }
            }
        }

        return dataToCopy;
    }

    void UndoRedo(bool redo = false){
        auto currentAction = redo ? RedoActions : UndoActions;
        if (currentAction.empty()){
            return;
        }

        Actions currentActionTop = currentAction.top();
        switch (currentActionTop.Action) {
            case ActionType::MemWrite:
            {
                if (WriteFn){
                    WriteFn(MemData, currentActionTop.startAddr, currentActionTop.originalData[0]);
                }

                std::swap(currentActionTop.operationData[0],  currentActionTop.originalData[0]);
                break;
            }
            case ActionType::MemWriteBatch:
            {
                if (WriteFn){
                    for (int i = 0; i < currentActionTop.operationSize; i++){
                        WriteFn(MemData, currentActionTop.startAddr + i, currentActionTop.originalData[i]);
                    }
                    std::swap(currentActionTop.operationData,  currentActionTop.originalData);
                }
                break;
            }
            case ActionType::SetBaseAddr:
            {
                if (SetBaseAddress2) {
                    SetBaseAddress2(currentActionTop.originalData[0], currentActionTop.operationSize);
                    std::swap(currentActionTop.operationData,  currentActionTop.originalData);
                }

                break;
            }
            default:
                break;
        }

        if (redo){
            UndoActions.push(currentActionTop);
            RedoActions.pop();
        }
        else{
            RedoActions.push(currentActionTop);
            UndoActions.pop();
        }
    }

    bool FillRangeWithByte(uint64_t address, size_t upto, char byte){
        Actions undoAction = {.Action = MemWriteBatch, .startAddr = address - BaseDisplayAddr, .endAddr = (address + upto) - BaseDisplayAddr, .operationSize = upto};
        if (WriteFn){
            for (auto i = 0; i < (upto); address++, i++){
                undoAction.originalData.push_back(MemData[address - BaseDisplayAddr]);
                undoAction.operationData.push_back(byte);
                WriteFn(MemData, address - BaseDisplayAddr, byte);
            }
            UndoActions.push(undoAction);
        }
        return true;
    }

    bool WriteVectorToMemory(const std::vector<intptr_t> &vec, bool PasteAll = false) {
        auto currentAddr = SelectionStartAddr;
        auto endAddr = SelectionEndAddr;

        if (currentAddr == -1){
            currentAddr = endAddr = HoveredAddr;
        }

        if (WriteFn) {
            if (PasteAll){
                Actions undoAction = {.Action = MemWriteBatch, .startAddr = currentAddr, .endAddr = currentAddr + vec.size(), .operationSize = vec.size(),
                        .operationData = vec};
                for (int i = 0; i < vec.size(); currentAddr++, i++) {
                    undoAction.originalData.push_back(MemData[currentAddr]);
                    WriteFn(MemData, currentAddr, vec[i]);
                }
                UndoActions.push(undoAction);
            }
            else{
                Actions undoAction = {.Action = MemWriteBatch, .startAddr = currentAddr,
                        .operationData = vec};

                for (int i = 0; currentAddr != endAddr + 1 && i < vec.size(); currentAddr++, i++) {
                    undoAction.originalData.push_back(MemData[currentAddr]);
                    WriteFn(MemData, currentAddr, vec[i]);
                }

                undoAction.endAddr = currentAddr + 1;
                undoAction.operationSize = currentAddr - (endAddr);
                UndoActions.push(undoAction);
            }

        }

        return true;
    }

    bool validateHex(char toValidate){
        if ((toValidate >= '0' && toValidate <= '9') || (toValidate >= 'A' && toValidate <= 'F') || (toValidate >= 'a' && toValidate <= 'f')) {
            return true;
        }
        else{
            return false;
        }
    }

    bool PasteWriteToMemory(bool PasteAll = false){
        std::string clipboardText = ImGui::GetClipboardText();
        std::vector<intptr_t> convertedInts;
        std::string hex;

        for (int i = 0; i < clipboardText.length(); i++){
            if (clipboardText[i] == ' '){
                continue;
            }

            if (validateHex(clipboardText[i]) && (i+1 <= clipboardText.length() && (validateHex(clipboardText[i+1])))){
                hex += clipboardText[i];
            }
            else{
                return false;
            }
            ++i;
            hex += clipboardText[i];
            convertedInts.push_back(std::strtol(hex.c_str(), nullptr, 16));
            hex.clear();
            hex = "";
        }

        WriteVectorToMemory(convertedInts, PasteAll);
        return false;
    }

    void DrawOptionsLine(const Sizes& s, void* mem_data, size_t mem_size, size_t base_display_addr, const char* contextMenuName = "context")
    {
        IM_UNUSED(mem_data);
        ImGuiStyle& style = ImGui::GetStyle();
        ImGui::GetStyle().Colors[ImGuiCol_HeaderHovered] = ImColor(0x18, 0x19, 0x26);
 
        // Use the context menu name passed from DrawContents
        if (ImGui::BeginPopup(contextMenuName))
        {
            // Add a unique ID scope for all menu items based on the memory address
            ImGui::PushID((void*)(uintptr_t)base_display_addr);
            
            ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[4]);
            if (ImGui::MenuItem("Undo", "CTRL + Z", false)){
                UndoRedo(false);
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Redo", "CTRL + Y", false)){
                UndoRedo(true);
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Copy", "CTRL + C", false)){
                ImGui::SetClipboardText(ReadMemory(SelectionStartAddr, SelectionEndAddr).c_str());
            }
            ImGui::Separator();
            if (ImGui::BeginMenu("Copy as")) {
                if (ImGui::MenuItem("C array")){
                    ImGui::SetClipboardText(GetDataToCopy(ReadMemory(SelectionStartAddr, SelectionEndAddr), true).c_str());
                }

                if (ImGui::MenuItem("Hex")){
                    ImGui::SetClipboardText(GetDataToCopy(ReadMemory(SelectionStartAddr, SelectionEndAddr), false).c_str());
                }
                ImGui::EndMenu();
            }

            ImGui::Separator();
            if (ImGui::MenuItem("Paste", "CTRL + V", false)){
                PasteWriteToMemory();
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Paste All", "CTRL + V", false)){
                PasteWriteToMemory(true);
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Select All", "CTRL + A", false)){
                SelectionStartAddr = 0;
                SelectionEndAddr = SelectionStartAddr + mem_size;
            }

            if (OptShowSetBaseAddrOption){
                ImGui::Separator();
                if (ImGui::MenuItem("Set Base Address", "CTRL + Shift + E", false)){
                    if (SetBaseAddress2){
                        SetBaseAddress2(0, 0);
                        KeepSetBaseAddrWindow = true;
                    }
                }
            }

            if (OptFillMemoryRange){
                ImGui::Separator();
                if (ImGui::MenuItem("Fill memory with byte",  nullptr)){
                    if (FillMemoryRange){
                        FillMemoryRange();
                        KeepFillMemoryWindow = true;
                    }
                }
            }

            ImGui::Separator();
            if (ImGui::MenuItem("Goto", "CTRL + G")){
                KeepGoToPopup = true;
            }
            ImGui::PopFont();
            
            // Pop the ID scope for menu items
            ImGui::PopID();
            
            ImGui::EndPopup();
        }

        ImGui::SameLine();
        
        // Add a unique ID scope for option buttons
        ImGui::PushID((void*)(uintptr_t)(base_display_addr + 1)); // Using a different value than the context menu
        
        if (!ShowRequiredButton){
            if (ImGui::Button("^^")){
                OptShowDataPreview = !OptShowDataPreview;
            }
            ImGui::SameLine();
            if (ImGui::Button("Aa")){
                OptUpperCaseHex = !OptUpperCaseHex;
            }
        }
        else{
            if (ShowRequiredButton("Preview", OptShowDataPreview)){
                OptShowDataPreview = !OptShowDataPreview;
            }
            ImGui::SameLine();
            if (ShowRequiredButton("Case", OptUpperCaseHex)){
                OptUpperCaseHex = !OptUpperCaseHex;
            }
            ImGui::SameLine();
            if (ShowRequiredButton("Ascii", OptShowAscii)){
                OptShowAscii = !OptShowAscii;
            }
            ImGui::SameLine();
       }
       
       // Pop ID for option buttons
       ImGui::PopID();

        if (GotoAddr != (size_t)-1)
        {
            if (GotoAddr < mem_size)
            {
                ImGui::BeginChild("##scrolling");
                ImGui::SetScrollFromPosY(ImGui::GetCursorStartPos().y + (GotoAddr / Cols) * ImGui::GetTextLineHeight());
                ImGui::EndChild();
                DataEditingAddr = DataPreviewAddr = GotoAddr;
                DataEditingTakeFocus = true;
            }
            GotoAddr = (size_t)-1;
        }
    }

    void DrawPreviewLine(const Sizes& s, void* mem_data_void, size_t mem_size, size_t base_display_addr)
    {
        // Add a unique ID scope for all preview line widgets
        ImGui::PushID((void*)(uintptr_t)(base_display_addr + 2)); // Using a different value than other ID scopes
        
        IM_UNUSED(base_display_addr);
        ImU8* mem_data = (ImU8*)mem_data_void;
        ImGuiStyle& style = ImGui::GetStyle();
        ImGui::AlignTextToFramePadding();
        ImGui::Text("Preview as:");
        ImGui::SameLine();
        ImGui::SetNextItemWidth((s.GlyphWidth * 10.0f) + style.FramePadding.x * 2.0f + style.ItemInnerSpacing.x);
        if (ImGui::BeginCombo("##combo_type", DataTypeGetDesc(PreviewDataType), ImGuiComboFlags_HeightLargest))
        {
            for (int n = 0; n < ImGuiDataType_COUNT; n++)
                if (ImGui::Selectable(DataTypeGetDesc((ImGuiDataType)n), PreviewDataType == n))
                    PreviewDataType = (ImGuiDataType)n;
            ImGui::EndCombo();
        }
        ImGui::SameLine();
        ImGui::SetNextItemWidth((s.GlyphWidth * 6.0f) + style.FramePadding.x * 2.0f + style.ItemInnerSpacing.x);
        ImGui::Combo("##combo_endianness", &PreviewEndianness, "LE\0BE\0\0");

        char buf[128] = "";
        float x = s.GlyphWidth * 6.0f;
        bool has_value = DataPreviewAddr != (size_t)-1;
        if (has_value)
            DrawPreviewData(DataPreviewAddr, mem_data, mem_size, PreviewDataType, DataFormat_Dec, buf, (size_t)IM_ARRAYSIZE(buf));
        ImGui::Text("Dec"); ImGui::SameLine(x); ImGui::TextUnformatted(has_value ? buf : "N/A");
        if (has_value)
            DrawPreviewData(DataPreviewAddr, mem_data, mem_size, PreviewDataType, DataFormat_Hex, buf, (size_t)IM_ARRAYSIZE(buf));
        ImGui::Text("Hex"); ImGui::SameLine(x); ImGui::TextUnformatted(has_value ? buf : "N/A");
        if (has_value)
            DrawPreviewData(DataPreviewAddr, mem_data, mem_size, PreviewDataType, DataFormat_Bin, buf, (size_t)IM_ARRAYSIZE(buf));
        buf[IM_ARRAYSIZE(buf) - 1] = 0;
        ImGui::Text("Bin"); ImGui::SameLine(x); ImGui::TextUnformatted(has_value ? buf : "N/A");
        
        // Pop the ID scope
        ImGui::PopID();
    }

    // Utilities for Data Preview
    const char* DataTypeGetDesc(ImGuiDataType data_type) const
    {
        const char* descs[] = { "Int8", "Uint8", "Int16", "Uint16", "Int32", "Uint32", "Int64", "Uint64", "Float", "Double" };
        IM_ASSERT(data_type >= 0 && data_type < ImGuiDataType_COUNT);
        return descs[data_type];
    }

    size_t DataTypeGetSize(ImGuiDataType data_type) const
    {
        const size_t sizes[] = { 1, 1, 2, 2, 4, 4, 8, 8, sizeof(float), sizeof(double) };
        IM_ASSERT(data_type >= 0 && data_type < ImGuiDataType_COUNT);
        return sizes[data_type];
    }

    const char* DataFormatGetDesc(DataFormat data_format) const
    {
        const char* descs[] = { "Bin", "Dec", "Hex" };
        IM_ASSERT(data_format >= 0 && data_format < DataFormat_COUNT);
        return descs[data_format];
    }

    bool IsBigEndian() const
    {
        uint16_t x = 1;
        char c[2];
        memcpy(c, &x, 2);
        return c[0] != 0;
    }

    static void* EndiannessCopyBigEndian(void* _dst, void* _src, size_t s, int is_little_endian)
    {
        if (is_little_endian)
        {
            uint8_t* dst = (uint8_t*)_dst;
            uint8_t* src = (uint8_t*)_src + s - 1;
            for (int i = 0, n = (int)s; i < n; ++i)
                memcpy(dst++, src--, 1);
            return _dst;
        }
        else
        {
            return memcpy(_dst, _src, s);
        }
    }

    static void* EndiannessCopyLittleEndian(void* _dst, void* _src, size_t s, int is_little_endian)
    {
        if (is_little_endian)
        {
            return memcpy(_dst, _src, s);
        }
        else
        {
            uint8_t* dst = (uint8_t*)_dst;
            uint8_t* src = (uint8_t*)_src + s - 1;
            for (int i = 0, n = (int)s; i < n; ++i)
                memcpy(dst++, src--, 1);
            return _dst;
        }
    }

    void* EndiannessCopy(void* dst, void* src, size_t size) const
    {
        static void* (*fp)(void*, void*, size_t, int) = NULL;
        if (fp == NULL)
            fp = IsBigEndian() ? EndiannessCopyBigEndian : EndiannessCopyLittleEndian;
        return fp(dst, src, size, PreviewEndianness);
    }

    const char* FormatBinary(const uint8_t* buf, int width) const
    {
        IM_ASSERT(width <= 64);
        size_t out_n = 0;
        static char out_buf[64 + 8 + 1];
        int n = width / 8;
        for (int j = n - 1; j >= 0; --j)
        {
            for (int i = 0; i < 8; ++i)
                out_buf[out_n++] = (buf[j] & (1 << (7 - i))) ? '1' : '0';
            out_buf[out_n++] = ' ';
        }
        IM_ASSERT(out_n < IM_ARRAYSIZE(out_buf));
        out_buf[out_n] = 0;
        return out_buf;
    }

    // [Internal]
    void DrawPreviewData(size_t addr, const ImU8* mem_data, size_t mem_size, ImGuiDataType data_type, DataFormat data_format, char* out_buf, size_t out_buf_size) const
    {
        uint8_t buf[8];
        size_t elem_size = DataTypeGetSize(data_type);
        size_t size = addr + elem_size > mem_size ? mem_size - addr : elem_size;
        if (ReadFn)
            for (int i = 0, n = (int)size; i < n; ++i)
                buf[i] = ReadFn(mem_data, addr + i);
        else
            memcpy(buf, mem_data + addr, size);

        if (data_format == DataFormat_Bin)
        {
            uint8_t binbuf[8];
            EndiannessCopy(binbuf, buf, size);
            ImSnprintf(out_buf, out_buf_size, "%s", FormatBinary(binbuf, (int)size * 8));
            return;
        }

        out_buf[0] = 0;
        switch (data_type)
        {
        case ImGuiDataType_S8:
        {
            int8_t int8 = 0;
            EndiannessCopy(&int8, buf, size);
            if (data_format == DataFormat_Dec) { ImSnprintf(out_buf, out_buf_size, "%hhd", int8); return; }
            if (data_format == DataFormat_Hex) { ImSnprintf(out_buf, out_buf_size, "0x%02x", int8 & 0xFF); return; }
            break;
        }
        case ImGuiDataType_U8:
        {
            uint8_t uint8 = 0;
            EndiannessCopy(&uint8, buf, size);
            if (data_format == DataFormat_Dec) { ImSnprintf(out_buf, out_buf_size, "%hhu", uint8); return; }
            if (data_format == DataFormat_Hex) { ImSnprintf(out_buf, out_buf_size, "0x%02x", uint8 & 0XFF); return; }
            break;
        }
        case ImGuiDataType_S16:
        {
            int16_t int16 = 0;
            EndiannessCopy(&int16, buf, size);
            if (data_format == DataFormat_Dec) { ImSnprintf(out_buf, out_buf_size, "%hd", int16); return; }
            if (data_format == DataFormat_Hex) { ImSnprintf(out_buf, out_buf_size, "0x%04x", int16 & 0xFFFF); return; }
            break;
        }
        case ImGuiDataType_U16:
        {
            uint16_t uint16 = 0;
            EndiannessCopy(&uint16, buf, size);
            if (data_format == DataFormat_Dec) { ImSnprintf(out_buf, out_buf_size, "%hu", uint16); return; }
            if (data_format == DataFormat_Hex) { ImSnprintf(out_buf, out_buf_size, "0x%04x", uint16 & 0xFFFF); return; }
            break;
        }
        case ImGuiDataType_S32:
        {
            int32_t int32 = 0;
            EndiannessCopy(&int32, buf, size);
            if (data_format == DataFormat_Dec) { ImSnprintf(out_buf, out_buf_size, "%d", int32); return; }
            if (data_format == DataFormat_Hex) { ImSnprintf(out_buf, out_buf_size, "0x%08x", int32); return; }
            break;
        }
        case ImGuiDataType_U32:
        {
            uint32_t uint32 = 0;
            EndiannessCopy(&uint32, buf, size);
            if (data_format == DataFormat_Dec) { ImSnprintf(out_buf, out_buf_size, "%u", uint32); return; }
            if (data_format == DataFormat_Hex) { ImSnprintf(out_buf, out_buf_size, "0x%08x", uint32); return; }
            break;
        }
        case ImGuiDataType_S64:
        {
            int64_t int64 = 0;
            EndiannessCopy(&int64, buf, size);
            if (data_format == DataFormat_Dec) { ImSnprintf(out_buf, out_buf_size, "%lld", (long long)int64); return; }
            if (data_format == DataFormat_Hex) { ImSnprintf(out_buf, out_buf_size, "0x%016llx", (long long)int64); return; }
            break;
        }
        case ImGuiDataType_U64:
        {
            uint64_t uint64 = 0;
            EndiannessCopy(&uint64, buf, size);
            if (data_format == DataFormat_Dec) { ImSnprintf(out_buf, out_buf_size, "%llu", (long long)uint64); return; }
            if (data_format == DataFormat_Hex) { ImSnprintf(out_buf, out_buf_size, "0x%016llx", (long long)uint64); return; }
            break;
        }
        case ImGuiDataType_Float:
        {
            float float32 = 0.0f;
            EndiannessCopy(&float32, buf, size);
            if (data_format == DataFormat_Dec) { ImSnprintf(out_buf, out_buf_size, "%f", float32); return; }
            if (data_format == DataFormat_Hex) { ImSnprintf(out_buf, out_buf_size, "%a", float32); return; }
            break;
        }
        case ImGuiDataType_Double:
        {
            double float64 = 0.0;
            EndiannessCopy(&float64, buf, size);
            if (data_format == DataFormat_Dec) { ImSnprintf(out_buf, out_buf_size, "%f", float64); return; }
            if (data_format == DataFormat_Hex) { ImSnprintf(out_buf, out_buf_size, "%a", float64); return; }
            break;
        }
        case ImGuiDataType_COUNT:
            break;
        } // Switch
        IM_ASSERT(0); // Shouldn't reach
    }
};

#undef _PRISizeT
#undef ImSnprintf

#ifdef _MSC_VER
#pragma warning (pop)
#endif
