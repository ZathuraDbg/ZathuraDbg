#include "dialogHeader.hpp"
std::string selectedFile = "/home/rc/Zathura-UI/src/test.asm";

std::string openFileDialog(){
    const char* fc = tinyfd_openFileDialog("Select assembly file", nullptr, 0, nullptr, "Assembly files", 0);
    if (fc != nullptr){
        std::string f(fc);

        if (!f.empty()){
            selectedFile = f;
                    LOG_DEBUG("User selected the file " << selectedFile);
            return selectedFile;
        }
    }

    LOG_DEBUG("No file was selected");
    return "";
}

std::string saveAsFileDialog(){
    const char* fc = tinyfd_saveFileDialog("Save assembly file", nullptr, NULL, nullptr, nullptr);

    if (fc != NULL){
        std::string f(fc);

        if (!f.empty()){
            selectedFile = f;
                    LOG_DEBUG("User selected the file " << selectedFile);
            return selectedFile;
        }
    }

    LOG_DEBUG("No file was selected");
    return "";
}