#include "dialogHeader.hpp"
std::string selectedFile = "/home/rc/Zathura-UI/src/test.asm";

bool fileDialogsSupported(){
    if (!pfd::settings::available())
    {
        LOG_ERROR("PFD file dialogs are not supported on this platform");
        pfd::message("Unsupported platform!",
                     "Sorry, File Dialogs are not available on this platform.\nPlease just copy paste the content of the file in the editor",
                     pfd::choice::ok,
                     pfd::icon::error);
        return false;
    }
    return true;
}

std::string openFileDialog(){
    if (!fileDialogsSupported()){
        return "";
    }

    pfd::settings::verbose(false);
    auto f = pfd::open_file("Choose files to read", pfd::path::home(),
                            { "Text Files (.asm .s)", "*.asm *.s",
                              "All Files", "*" },
                            pfd::opt::none);

    if (!f.result().empty()){
        selectedFile = f.result()[0];
        LOG_DEBUG("User selected the file " << selectedFile);
        return selectedFile;
    }

    LOG_DEBUG("No file was selected");
    return "";
}

std::string saveAsFileDialog(){
    if (!fileDialogsSupported()){
        return "";
    }

    auto f = pfd::save_file("Choose file to save",
                            pfd::path::home() + pfd::path::separator() + "readme.txt",
                            { "Text Files (.asm .s)", "*.asm *.s" },
                            pfd::opt::force_overwrite);

    if (!f.result().empty()){
        LOG_DEBUG("User selected the file " << f.result());
        return f.result();
    }


    LOG_DEBUG("No file was selected" << f.result());
    return "";
}