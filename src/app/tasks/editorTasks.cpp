#include "editorTasks.hpp"

TextEditor *editor = nullptr;

bool writeEditorToFile(const std::string& filePath) {
    LOG_DEBUG("Writing to file " << filePath);
    std::ofstream out(filePath, std::ios::out | std::ios::trunc);

    if (out.good()){
        out << editor->GetText();
        out.close();
        LOG_DEBUG("Done!");
        return true;
    }

    tinyfd_messageBox("File write error!", ("Unable to write to the file " + filePath + "!\nPlease check if the "
                                                                                        "file is not open in another program and/or you have the permissions to read it.").c_str(), "ok", "error", 0);
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
    tinyfd_messageBox("File read error!", ("Unable to read from the file " + filePath + "!\nPlease check if the "
                            "file is not open in another program and/or you have the permissions to read it.").c_str(), "ok", "error", 0);

    return false;
}