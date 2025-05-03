#include "fileTasks.hpp"
#include <mutex>
#include "../app.hpp"

std::filesystem::path getTemporaryPath(){
    std::filesystem::path tempDir;
    try{
         tempDir = std::filesystem::temp_directory_path();
    }
    catch (const std::filesystem::filesystem_error& e){
        LOG_NOTICE("Temporary directory not found...\n"
                   "Using current directory for saving temp files");
        tempDir = std::filesystem::current_path();
    }

    return tempDir;
}

static std::mutex icicleMutex;

bool fileOpenTask(const std::string& fileName){
    if (!fileName.empty()){
        LOG_DEBUG("Opening the file " << fileName);
        if (!readFileIntoEditor(fileName)){
            LOG_ERROR("Read operation failed on the file: " << fileName);
            return false;
        }

        selectedFile = fileName;
        editor->HighlightBreakpoints(-1);
        resetState(false);
        getBytes(fileName);
        initInsSizeInfoMap();
        LOG_INFO("The provided file " << fileName << " opened successfully.");
        return true;
    }

    return true;
}

void fileSaveAsTask(const std::string &fileName){
    if (!fileName.empty()) {
        LOG_DEBUG("Saving the file " << fileName);
        if (!writeEditorToFile(fileName)) {
            LOG_ERROR("Save as operation failed on the file: " << fileName << " !");
        }
        selectedFile = fileName;
    }
}

void fileSaveTask(const std::string &fileName){
    if (!fileName.empty()){
        LOG_DEBUG("Saving the file " << fileName);
        if (!writeEditorToFile(selectedFile)) {
            LOG_ERROR("Save operation failed on the file: " << fileName << " !");
        }

        selectedFile = fileName;
        fileOpenTask(selectedFile);
    }
}


bool fileRunTask(const bool& execCode){
    if (!selectedFile.empty()){
        LOG_DEBUG("Running code from: " << selectedFile);

        { // Lock scope for icicle cleanup
            std::lock_guard<std::mutex> lock(icicleMutex);
            if (icicle != nullptr){
                icicle_free(icicle);
                icicle = nullptr;
            }
        }

        if (createStack(icicle)){
            const std::string bytes = getBytes(selectedFile);
            if (!bytes.empty()){
                runCode(bytes, execCode);
            }
            else {
                LOG_ERROR("Unable to run the code. Either no code is present or invalid architecture is selected.");
                return false;
            }
        }
        else{
            tinyfd_messageBox("Stack creation failed!", "The app was unable to create the stack to run the code.\nPlease try restarting it or report this issue on github!",
                "ok", "error", 0);

            LOG_ERROR("Unable to create stack!, quitting!");
            return false;
        }
    }
    else{
        LOG_ERROR("No file selected to run!");
        tinyfd_messageBox("No file selected!", "Please open a file to run the code!", "ok", "error", 0);
        return false;
    }

    return true;
}

bool serializeState()
{
    if (!icicle)
    {
        LOG_INFO("No active state to serialize.");
        return false;
    }

    const char* fileName = tinyfd_saveFileDialog("Select a file to serialize into", NULL, NULL, NULL, NULL);
    if (!fileName)
    {
        LOG_ERROR("No file selected...");
        return false;
    }

    const auto ret = icicle_serialize_vm_state(icicle, fileName, true, 3);
    if (ret != 0){
       LOG_ERROR("Failed to serialize into file " << fileName);
        return false;
    }

    LOG_INFO("Successfully serialized into file " << fileName);
    return true;
}

bool deserializeState()
{
    LOG_INFO("Deserializing into file " << selectedFile);

    if (!icicle && !debugModeEnabled)
    {
        LOG_INFO("Enabling the debug mode...");
        startDebugging();
    }

    const char* fileName = tinyfd_openFileDialog("Select file to deserialize", NULL, NULL, NULL, NULL, NULL);
    if (fileName == NULL)
    {
        LOG_INFO("No file selected. Stopping debugging...");
        debugStop = true;
        return false;
    }
    else
    {
        LOG_INFO("Deserializing state...");
        const int f = icicle_deserialize_vm_state(icicle, fileName, true, 3);
        if (f != 0)
        {
            LOG_ERROR("Failed to deserialize into file " << fileName);
            return false;
        }
    }

    LOG_INFO("Successfully deserialized from file " << fileName);
    safeHighlightLine(addressToLineNo(icicle_get_pc(icicle)));
    return true;
}