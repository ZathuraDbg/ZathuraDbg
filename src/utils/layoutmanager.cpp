#include <optional>
#include "../app/app.hpp"
#include "layoutmanager.h"

namespace Utils{

    namespace {

        std::string s_layoutPathToLoad;
        std::string s_layoutStringToLoad;
        std::vector<LayoutManager::Layout> s_layouts;
        std::vector<LayoutManager::StoreCallback> s_storeCallbacks;
        std::vector<LayoutManager::LoadCallback> s_loadCallbacks;

        bool s_layoutLocked = false;
    }


    void LayoutManager::load(const std::filesystem::path &path) {
        s_layoutPathToLoad = path;
    }

    void LayoutManager::loadFromString(const std::string &content) {
        s_layoutStringToLoad = content;
    }

    void LayoutManager::save(const std::string &name) {
        auto fileName = name;
        fileName = "config";
        fileName += ".zlyt";

        std::filesystem::path layoutPath;

        std::string pathString = executablePath;
        pathString += "/";
        pathString += fileName; ImGui::SaveIniSettingsToDisk(pathString.c_str()); LayoutManager::reload();
    }

    std::string LayoutManager::saveToString() {
        return ImGui::SaveIniSettingsToMemory();
    }

    void LayoutManager::process() {
        if (!s_layoutPathToLoad.empty()) {
            std::string pathString = executablePath;
            pathString += "/";
            ImGui::LoadIniSettingsFromDisk(pathString.c_str());

            s_layoutPathToLoad.clear() ;
        }

        if (!s_layoutStringToLoad.empty()) {
            ImGui::LoadIniSettingsFromMemory((s_layoutStringToLoad).c_str());
            s_layoutStringToLoad.clear();
        }
    }

    void LayoutManager::reload() {
        s_layouts.clear();

        for (const auto &directory : {executablePath + "/"})
            for (const auto &entry : std::filesystem::directory_iterator(directory)) {
                const auto &path = entry.path();

                if (path.extension() != ".zlyt")
                    continue;

                auto name = path.stem().string();
                for (size_t i = 0; i < name.size(); i++) {
                    if (i == 0 || name[i - 1] == '_')
                        name[i] = char(std::toupper(name[i]));
                }

                s_layouts.push_back({
                    (std::string)name,
                    path
                });
            }
        }

    void LayoutManager::reset() {
        s_layoutPathToLoad.clear();
        s_layoutStringToLoad.clear();
    }

    bool LayoutManager::isLayoutLocked() {
        return s_layoutLocked;
    }

    void LayoutManager::lockLayout(bool locked) {
        s_layoutLocked = locked;
    }

    void LayoutManager::registerLoadCallback(const LoadCallback &callback) {
        s_loadCallbacks.push_back(callback);
    }

    void LayoutManager::registerStoreCallback(const StoreCallback &callback) {
        s_storeCallbacks.push_back(callback);
    }

}
