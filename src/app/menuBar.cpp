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

    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[RubikRegular16]);
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
                if (editor->CanUndo()){
                    editor->Undo();
                    LOG_INFO("Editor serviced undo");
                }
                else{
                    LOG_ERROR("Undo requested but couldn't be fulfilled by editor");
                }
            }
            if (ImGui::MenuItem("Redo", "CTRL+Y", false)) {
                if (editor->CanRedo()){
                    editor->Redo();
                    LOG_INFO("Editor serviced redo");
                }
                else{
                    LOG_ERROR("Redo requested but couldn't be fulfilled by editor");
                }

            }
            ImGui::Separator();
            if (ImGui::MenuItem("Cut", "CTRL+X")) {
                editor->Cut();
                LOG_INFO("Editor cut to clipboard");
            }
            if (ImGui::MenuItem("Copy", "CTRL+C")) {
                editor->Copy();
                LOG_INFO("Editor copied to clipboard");
            }
            if (ImGui::MenuItem("Paste", "CTRL+V")) {
                editor->Paste();
                LOG_INFO("Editor pasted from clipboard");
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
        LOG_INFO("File open dialog requested!");
        fileOpenTask(openFileDialog());
    }
    if (fileSaveAs) {
        LOG_INFO("File save as dialog requested!");
        fileSaveAsTask( saveAsFileDialog());
    }
    if (fileSave){
        LOG_INFO("File save requested for the file: " << selectedFile);
        fileSaveTask(selectedFile);
    }

    ImGui::PopFont();
}