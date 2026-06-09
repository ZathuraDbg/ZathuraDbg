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

#endif  // __EMSCRIPTEN__
