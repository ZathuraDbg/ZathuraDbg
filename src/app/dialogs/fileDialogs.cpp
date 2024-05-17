#include "dialogHeader.hpp"

std::string selectedFile;

std::string openFileDialog(){
    if (!pfd::settings::available())
    {
        pfd::message("Unsupported platform!",
                     "Sorry, file Dialogs are not available on this platform.\nPlease just copy paste the content of the file in the editor",
                     pfd::choice::ok,
                     pfd::icon::error);
    }

    pfd::settings::verbose(false);

    auto f = pfd::open_file("Choose files to read", pfd::path::home(),
                            { "Text Files (.asm .s)", "*.asm *.s",
                              "All Files", "*" },
                            pfd::opt::none);
    if (!f.result().empty()){
        selectedFile = f.result()[0];
        return selectedFile;
    }

    return "";
}

std::string saveAsFileDialog(){
    auto f = pfd::save_file("Choose file to save",
                            pfd::path::home() + pfd::path::separator() + "readme.txt",
                            { "Text Files (.asm .s)", "*.asm *.s" },
                            pfd::opt::force_overwrite);
    std::cout << "Selected file: " << f.result() << "\n";

    if (!f.result().empty()){
        return f.result();
    }
    return "";
}
