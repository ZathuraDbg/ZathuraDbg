#include "dialogHeader.hpp"
std::string selectedFile = std::filesystem::current_path().concat("/test.asm").make_preferred().string();

std::string openFileDialog(){
    const char* chosenFile = tinyfd_openFileDialog("Select desired file", nullptr, 0, nullptr, "Assembly files", 0);
    if (chosenFile != nullptr){
        const std::string chosenFileString(chosenFile);

        if (!chosenFileString.empty()){
            LOG_DEBUG("User selected the file " << chosenFile);
            return chosenFileString;
        }
    }

    LOG_DEBUG("No file was selected");
    return "";
}

std::string saveAsFileDialog(){
    const char* chosenFile = tinyfd_saveFileDialog("Save assembly file", nullptr, 0, nullptr, nullptr);

    if (chosenFile != nullptr){
        const std::string chosenFileString(chosenFile);

        if (!chosenFileString.empty()){
            LOG_DEBUG("User selected the file " << selectedFile);
            return chosenFileString;
        }
    }

    LOG_DEBUG("No file was selected");
    return "";
}
