#pragma once
// Browser-backed file open/save and shareable-link support for the wasm build.
// Only declared/defined under Emscripten; callers gate on __EMSCRIPTEN__.
#ifdef __EMSCRIPTEN__

#include <string>

// Opens a browser file picker; the chosen file is written into MEMFS and loaded
// into the editor asynchronously (via fileOpenTask).
void browserOpenFile();

// Downloads the current editor contents as a file with the given suggested name.
void browserSaveEditor(const std::string& suggestedName);

// A reasonable download filename derived from the current selectedFile basename
// (defaults to "program.asm").
std::string browserDownloadName();

// Encodes the current editor contents into the page URL (#code=...) and copies
// the shareable link to the clipboard.
void browserShareCode();

// If the page URL carries a shared program (#code=...), writes it to a MEMFS
// file and points `selectedFile` at it so setupEditor() loads it. Returns true
// if a shared program was loaded. Call before setupEditor().
bool browserLoadCodeFromUrl();

// --- localStorage persistence -------------------------------------------------

// If a previously-edited program is saved in localStorage, materialise it and
// point `selectedFile` at it. Returns true if restored. Call before
// setupEditor() and only if no shared (#code) program was loaded.
bool browserRestoreSavedCode();

// Restore the window layout from localStorage if present, otherwise from the
// embedded default layout. Call after ImGui::CreateContext().
void browserRestoreLayout();

// Per-frame autosave: persists the editor program (throttled) and the window
// layout (when ImGui flags a change) to localStorage. Call once per frame.
void browserPersistTick();

// True when running on an Apple platform (macOS/iOS), so the UI can use Cmd as
// the shortcut modifier instead of Ctrl. The native build decides this at
// compile time via __APPLE__; the wasm build must detect it at runtime.
bool browserIsApplePlatform();

#endif  // __EMSCRIPTEN__
