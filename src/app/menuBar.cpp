#include "app.hpp"

void appMenuBar()
{
    bool fileOpen = false;
    bool fileSave = false;
    bool fileSaveAs = false;
    bool quit = false;  // not using exit because it's a function from std to avoid confusion

    bool debugRestart = false;
    bool debugStep = false;
    bool debugRun = false;
    bool debugPause = false;

    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[4]);
    if (ImGui::BeginMainMenuBar())
    {
        if (ImGui::BeginMenu("File"))
        {
            ImGui::MenuItem("Open", "Ctrl+O", &fileOpen);
            ImGui::MenuItem("Save", "Ctrl+S", &fileSave);
            ImGui::MenuItem("Save As", "Ctrl+Shift+S", &fileSaveAs);
            ImGui::Separator();
            ImGui::MenuItem("Exit", "Alt+F4", &quit);
            ImGui::Separator();
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Edit"))
        {
            if (ImGui::MenuItem("Undo", "CTRL+Z")) {
                if (editor->CanUndo())
                    editor->Undo();
            }
            if (ImGui::MenuItem("Redo", "CTRL+Y", false)) {
                if (editor->CanRedo())
                    editor->Redo();
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Cut", "CTRL+X")) {
                editor->Cut();
            }
            if (ImGui::MenuItem("Copy", "CTRL+C")) {
                editor->Copy();
            }
            if (ImGui::MenuItem("Paste", "CTRL+V")) {
                editor->Paste();
            }
            ImGui::Separator();
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Debug")){
            ImGui::MenuItem("Restart", "CTRL+R", &debugRestart);
            ImGui::MenuItem("Step", "CTRL+J", &debugStep);
            ImGui::MenuItem("Pause", "CTRL+P", &debugPause);
            ImGui::Separator();
            ImGui::EndMenu();
        }
        ImGui::EndMainMenuBar();
    }

    if (fileOpen)
    {
        fileOpenTask(openFileDialog());
    }
    if (fileSaveAs) {
        fileSaveAsTask( saveAsFileDialog());
    }
    if (fileSave){
        fileSaveTask(selectedFile);
    }

    ImGui::PopFont();
}
