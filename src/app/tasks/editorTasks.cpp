#include "editorTasks.hpp"

TextEditor *editor = nullptr;

bool writeEditorToFile(const std::string& filePath) {
    std::ofstream out(filePath, std::ios::out | std::ios::trunc);

    if (out.good()){
        std::cout << editor->GetText() << std::endl;
        out << editor->GetText();
        out.close();
        return true;
    }

    return false;
}

bool readFileIntoEditor(const std::string& filePath){
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