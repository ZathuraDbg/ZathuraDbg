#include "editorTasks.hpp"

TextEditor *editor = nullptr;

bool writeEditorToFile(const std::string& filePath) {
    LOG_DEBUG("Writing to file " << filePath);
    std::ofstream out(filePath, std::ios::out | std::ios::trunc);

    if (out.good()){
        out << editor->GetText();
        out.close();
        LOG_DEBUG("Done!");
    }

    LOG_ERROR("Failed to write to file.");
    return false;
}

bool readFileIntoEditor(const std::string& filePath){
    LOG_DEBUG("Read into editor");
    std::ifstream t(filePath);

    if (t.good())
    {
        std::string str((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());
        editor->SetText(str);
        t.close();
        return true;
    }

    return false;
}