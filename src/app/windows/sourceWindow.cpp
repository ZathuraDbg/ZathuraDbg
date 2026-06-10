#include "windows.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <memory>
#include <sstream>
#include <vector>

namespace {

std::unique_ptr<TextEditor> remoteSourceEditor;
bool remoteSourceEditorInitialized = false;
std::string manualRemoteSourceFile;
std::string loadedSourceFile;
std::string loadedSourceText;
uint64_t displayedSourceLine = 0;
std::vector<std::pair<std::string, std::string>> sourcePathRemaps;

void initRemoteSourceEditor() {
    if (remoteSourceEditorInitialized) {
        return;
    }

    remoteSourceEditor = std::make_unique<TextEditor>();
    remoteSourceEditor->SetPalette(TextEditor::PaletteId::Catppuccin);
    remoteSourceEditor->SetLanguageDefinition(TextEditor::LanguageDefinitionId::None);
    remoteSourceEditor->SetShowWhitespacesEnabled(false);
    remoteSourceEditor->SetReadOnlyEnabled(true);
    remoteSourceEditor->SetTabSize(4);
    remoteSourceEditor->SetText("; Remote source is available after loading a symbol file with DWARF line info.");
    remoteSourceEditorInitialized = true;
}

std::string readSourceFile(const std::string& path) {
    std::ifstream input(path);
    if (!input.good()) {
        return {};
    }

    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

std::string formatAddress(const uint64_t address) {
    std::ostringstream out;
    out << "0x" << std::hex << address;
    return out.str();
}

bool fileExists(const std::string& path) {
    if (path.empty()) {
        return false;
    }

    std::error_code ec;
    return std::filesystem::exists(path, ec) && std::filesystem::is_regular_file(path, ec);
}

std::string remapSourcePath(const std::string& path) {
    if (path.empty()) {
        return {};
    }

    for (const auto& [from, to] : sourcePathRemaps) {
        if (from.empty() || to.empty() || !path.starts_with(from)) {
            continue;
        }

        const auto suffix = path.substr(from.size());
        return (std::filesystem::path(to) / std::filesystem::path(suffix).relative_path()).lexically_normal().string();
    }

    return path;
}

void setRemoteSourceEditorText(const std::string& path, const std::string& text) {
    if (loadedSourceFile == path && loadedSourceText == text) {
        return;
    }

    remoteSourceEditor->SetReadOnlyEnabled(false);
    remoteSourceEditor->SetText(text);
    remoteSourceEditor->SetReadOnlyEnabled(true);
    loadedSourceFile = path;
    loadedSourceText = text;
    displayedSourceLine = 0;
}

void highlightRemoteSourceLine(const uint64_t line) {
    if (displayedSourceLine == line) {
        return;
    }

    if (line == 0) {
        remoteSourceEditor->HighlightDebugCurrentLine(-1);
        displayedSourceLine = 0;
        return;
    }

    const int lineIndex = static_cast<int>(line - 1);
    const int clampedLineIndex = std::max(0, std::min(lineIndex, remoteSourceEditor->GetLineCount() - 1));
    remoteSourceEditor->HighlightDebugCurrentLine(clampedLineIndex);
    remoteSourceEditor->SetCursorPosition(clampedLineIndex, 0);
    remoteSourceEditor->SetViewAtLine(clampedLineIndex, TextEditor::SetViewAtLineMode::Centered);
    displayedSourceLine = line;
}

std::optional<remote_gdb::SourceLocation> currentSourceLocation() {
    if (!remote_gdb::remoteDebugConnected()) {
        return std::nullopt;
    }

    const auto pc = remote_gdb::remoteProgramCounter();
    if (!pc.has_value()) {
        return std::nullopt;
    }

    return remote_gdb::findSourceLocationForAddress(remote_gdb::remoteLoadedSymbols(), *pc);
}

}

void setRemoteSourceFile(const std::string& path) {
    manualRemoteSourceFile = path;
    loadedSourceFile.clear();
    loadedSourceText.clear();
    displayedSourceLine = 0;
}

void clearRemoteSourceFile() {
    manualRemoteSourceFile.clear();
    loadedSourceFile.clear();
    loadedSourceText.clear();
    displayedSourceLine = 0;
}

void addRemoteSourcePathRemap(const std::string& from, const std::string& to) {
    if (from.empty() || to.empty()) {
        return;
    }

    for (auto& remap : sourcePathRemaps) {
        if (remap.first == from) {
            remap.second = to;
            loadedSourceFile.clear();
            loadedSourceText.clear();
            displayedSourceLine = 0;
            return;
        }
    }

    sourcePathRemaps.emplace_back(from, to);
    loadedSourceFile.clear();
    loadedSourceText.clear();
    displayedSourceLine = 0;
}

void clearRemoteSourcePathRemaps() {
    sourcePathRemaps.clear();
    loadedSourceFile.clear();
    loadedSourceText.clear();
    displayedSourceLine = 0;
}

std::string applyRemoteSourcePathRemaps(const std::string& path) {
    return remapSourcePath(path);
}

static void renderSourceControls() {
    static char symbolFilePath[512] = "";
    static char remapFrom[256] = "";
    static char remapTo[256] = "";

    const auto& symbols = remote_gdb::remoteLoadedSymbols();
    ImGui::Text("Symbols: %zu names, %zu source rows",
                symbols.addrToName.size(),
                symbols.addrToSourceLine.size());

    ImGui::SetNextItemWidth(-120);
    ImGui::InputTextWithHint("##symbolFilePath", "ELF symbol file", symbolFilePath, IM_ARRAYSIZE(symbolFilePath));
    ImGui::SameLine();
    if (ImGui::Button("Load")) {
        if (remote_gdb::remoteLoadSymbolFile(symbolFilePath)) {
            consoleWriteThreadSafe("remote >> loaded symbols from " + std::string(symbolFilePath) + "\n");
            if (remote_gdb::remoteDebugConnected()) {
                requestRemoteUiSync(false);
            }
        } else {
            consoleWriteThreadSafe("remote >> failed to load symbols from " + std::string(symbolFilePath) + "\n");
        }
    }

    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x * 0.45f);
    ImGui::InputTextWithHint("##sourceRemapFrom", "debug path prefix", remapFrom, IM_ARRAYSIZE(remapFrom));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x - 80.0f);
    ImGui::InputTextWithHint("##sourceRemapTo", "local path prefix", remapTo, IM_ARRAYSIZE(remapTo));
    ImGui::SameLine();
    if (ImGui::Button("Map")) {
        addRemoteSourcePathRemap(remapFrom, remapTo);
        remapFrom[0] = '\0';
        remapTo[0] = '\0';
    }

    if (!sourcePathRemaps.empty()) {
        if (ImGui::BeginTable("SourceRemaps", 3,
                              ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) {
            ImGui::TableSetupColumn("Debug prefix");
            ImGui::TableSetupColumn("Local prefix");
            ImGui::TableSetupColumn("Action");
            ImGui::TableHeadersRow();

            for (size_t i = 0; i < sourcePathRemaps.size(); ++i) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::TextUnformatted(sourcePathRemaps[i].first.c_str());
                ImGui::TableSetColumnIndex(1);
                ImGui::TextUnformatted(sourcePathRemaps[i].second.c_str());
                ImGui::TableSetColumnIndex(2);
                ImGui::PushID(static_cast<int>(i));
                if (ImGui::Button("Delete")) {
                    sourcePathRemaps.erase(sourcePathRemaps.begin() + static_cast<std::ptrdiff_t>(i));
                    loadedSourceFile.clear();
                    loadedSourceText.clear();
                    displayedSourceLine = 0;
                    ImGui::PopID();
                    break;
                }
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
    }
}

void remoteSourceWindow() {
    initRemoteSourceEditor();
    renderSourceControls();
    ImGui::Separator();

    std::optional<uint64_t> pc;
    if (remote_gdb::useRemoteDebugging() && remote_gdb::remoteDebugConnected()) {
        pc = remote_gdb::remoteProgramCounter();
    }
    const auto location = currentSourceLocation();

    std::string sourcePath;
    uint64_t sourceLine = 0;

    if (location.has_value()) {
        sourcePath = applyRemoteSourcePathRemaps(location->file);
        sourceLine = location->line;
        if (!fileExists(sourcePath) && !manualRemoteSourceFile.empty()) {
            sourcePath = manualRemoteSourceFile;
        }
    } else if (!manualRemoteSourceFile.empty()) {
        sourcePath = manualRemoteSourceFile;
    }

    if (!sourcePath.empty()) {
        const std::string sourceText = readSourceFile(sourcePath);
        if (!sourceText.empty()) {
            setRemoteSourceEditorText(sourcePath, sourceText);
            highlightRemoteSourceLine(sourceLine);
        } else {
            setRemoteSourceEditorText(sourcePath, "; Unable to open source file: " + sourcePath);
            highlightRemoteSourceLine(0);
        }
    } else if (remote_gdb::useRemoteDebugging()) {
        setRemoteSourceEditorText("", "; No source line is available for the current remote target.");
        highlightRemoteSourceLine(0);
    } else {
        setRemoteSourceEditorText("", "; Remote source panel is inactive outside Remote GDB mode.");
        highlightRemoteSourceLine(0);
    }

    if (pc.has_value()) {
        ImGui::Text("PC: %s", formatAddress(*pc).c_str());
    } else {
        ImGui::TextUnformatted("PC: unavailable");
    }

    if (!sourcePath.empty()) {
        if (sourceLine > 0) {
            ImGui::Text("Source: %s:%llu",
                        sourcePath.c_str(),
                        static_cast<unsigned long long>(sourceLine));
        } else {
            ImGui::Text("Source: %s", sourcePath.c_str());
        }
    } else {
        ImGui::TextUnformatted("Source: unavailable");
    }

    ImGui::Separator();
    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[JetBrainsMono20]);
    remoteSourceEditor->Render("RemoteSourceEditor");
    ImGui::PopFont();
}
