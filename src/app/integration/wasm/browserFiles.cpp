#ifdef __EMSCRIPTEN__
#include "browserFiles.hpp"

#include <emscripten.h>

#include "../../tasks/editorTasks.hpp"   // editor, readFileIntoEditor
#include "../../tasks/fileTasks.hpp"     // fileOpenTask
#include "../../dialogs/dialogHeader.hpp" // selectedFile

// Path under MEMFS where browser-sourced programs are materialised so the
// existing file pipeline (fileOpenTask / setupEditor) can consume them.
static const char* kOpenedPath = "/app/bin/opened.asm";
static const char* kSharedPath = "/app/bin/shared.asm";

// --- JavaScript helpers -------------------------------------------------------

// Show a file picker; on selection, write the file into MEMFS and call back into
// C to load it. Asynchronous: returns immediately.
EM_JS(void, zathura_js_open_file, (const char* destC), {
    const dest = UTF8ToString(destC);
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.asm,.s,.inc,.txt,text/plain';
    input.onchange = (e) => {
        const file = e.target.files && e.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = () => {
            const data = new Uint8Array(reader.result);
            try { FS.writeFile(dest, data); } catch (err) { console.error('write failed', err); return; }
            Module.ccall('zathura_open_memfs_file', null, ['string'], [dest]);
        };
        reader.readAsArrayBuffer(file);
    };
    input.click();
});

// Trigger a browser download of `len` bytes at `dataC` as `nameC`.
EM_JS(void, zathura_js_download, (const char* nameC, const char* dataC, int len), {
    const name = UTF8ToString(nameC);
    const bytes = HEAPU8.slice(dataC, dataC + len);
    const blob = new Blob([bytes], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
});

// Encode `textC` into the URL hash and copy the resulting link to the clipboard.
EM_JS(void, zathura_js_share, (const char* textC), {
    const text = UTF8ToString(textC);
    const b64 = btoa(unescape(encodeURIComponent(text)));
    const hash = '#code=' + b64;
    history.replaceState(null, '', location.pathname + hash);
    const url = location.origin + location.pathname + hash;
    if (navigator.clipboard) { navigator.clipboard.writeText(url).catch(() => {}); }
    console.log('[zathura] share link copied to clipboard');
});

// If the URL carries #code=..., decode it into the MEMFS file `destC`.
// Returns 1 if a shared program was written, 0 otherwise.
EM_JS(int, zathura_js_url_code_to_file, (const char* destC), {
    const m = (location.hash || '').match(/[#&]code=([^&]+)/);
    if (!m) return 0;
    let text;
    try { text = decodeURIComponent(escape(atob(m[1]))); } catch (e) { return 0; }
    const dest = UTF8ToString(destC);
    try { FS.writeFile(dest, text); } catch (e) { return 0; }
    return 1;
});

// localStorage set/get. get writes the value into a MEMFS file so the existing
// file pipeline can consume it; returns 1 if the key existed.
EM_JS(void, zathura_js_ls_set, (const char* keyC, const char* valC), {
    try { localStorage.setItem(UTF8ToString(keyC), UTF8ToString(valC)); } catch (e) {}
});

EM_JS(int, zathura_js_ls_get_to_file, (const char* keyC, const char* destC), {
    let v;
    try { v = localStorage.getItem(UTF8ToString(keyC)); } catch (e) { return 0; }
    if (v === null) return 0;
    try { FS.writeFile(UTF8ToString(destC), v); } catch (e) { return 0; }
    return 1;
});

EM_JS(int, zathura_js_is_apple, (), {
    try {
        const p = (navigator.userAgentData && navigator.userAgentData.platform)
                  || navigator.platform || navigator.userAgent || '';
        return /mac|iphone|ipad|ipod/i.test(p) ? 1 : 0;
    } catch (e) { return 0; }
});

// --- C entry points -----------------------------------------------------------

// Called from JS once a picked file has been written into MEMFS.
extern "C" EMSCRIPTEN_KEEPALIVE void zathura_open_memfs_file(const char* path) {
    fileOpenTask(std::string(path));
}

void browserOpenFile() {
    zathura_js_open_file(kOpenedPath);
}

void browserSaveEditor(const std::string& suggestedName) {
    const std::string text = editor->GetText();
    zathura_js_download(suggestedName.c_str(), text.c_str(), static_cast<int>(text.size()));
}

void browserShareCode() {
    zathura_js_share(editor->GetText().c_str());
}

std::string browserDownloadName() {
    const auto slash = selectedFile.find_last_of('/');
    std::string base = (slash == std::string::npos) ? selectedFile
                                                    : selectedFile.substr(slash + 1);
    if (base.empty() || base == "shared.asm" || base == "opened.asm") {
        return "program.asm";
    }
    return base;
}

bool browserLoadCodeFromUrl() {
    if (zathura_js_url_code_to_file(kSharedPath)) {
        selectedFile = kSharedPath;
        return true;
    }
    return false;
}

// --- localStorage persistence -------------------------------------------------

static const char* kCodeKey = "zathura.code";
static const char* kLayoutKey = "zathura.layout";
static const char* kLayoutFile = "/tmp/zathura_layout.ini";

bool browserRestoreSavedCode() {
    if (zathura_js_ls_get_to_file(kCodeKey, kSharedPath)) {
        selectedFile = kSharedPath;
        return true;
    }
    return false;
}

void browserRestoreLayout() {
    if (zathura_js_ls_get_to_file(kLayoutKey, kLayoutFile)) {
        ImGui::LoadIniSettingsFromDisk(kLayoutFile);
    } else {
        ImGui::LoadIniSettingsFromDisk("/app/config.zlyt");
    }
}

bool browserIsApplePlatform() {
    return zathura_js_is_apple() != 0;
}

void browserPersistTick() {
    ImGuiIO& io = ImGui::GetIO();

    // Layout: persist whenever ImGui reports a change.
    if (io.WantSaveIniSettings) {
        if (const char* ini = ImGui::SaveIniSettingsToMemory(nullptr)) {
            zathura_js_ls_set(kLayoutKey, ini);
        }
        io.WantSaveIniSettings = false;
    }

    // Editor program: diff against the last save every ~30 frames (cheap for
    // the small programs this tool edits) and persist on change.
    static int frames = 0;
    static std::string lastSaved;
    if (editor && ++frames >= 30) {
        frames = 0;
        std::string text = editor->GetText();
        if (text != lastSaved) {
            zathura_js_ls_set(kCodeKey, text.c_str());
            lastSaved = std::move(text);
        }
    }
}
#endif  // __EMSCRIPTEN__
