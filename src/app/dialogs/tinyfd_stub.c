/* Emscripten/wasm stub for tinyfiledialogs.
 *
 * Native dialogs (zenity/kdialog/osascript) do not exist in the browser, so
 * the wasm build replaces tinyfiledialogs.c with these inert implementations.
 * Message/notify popups are routed to the JS console; all file/color/input
 * dialogs report "cancelled" (NULL / default button). Browser-native file
 * pickers can be wired in later through a JS shim if needed.
 */

#include <stdio.h>

#ifdef __EMSCRIPTEN__
#include <emscripten/emscripten.h>
#endif

/* Public globals declared in tinyfiledialogs.h */
int tinyfd_verbose = 0;
int tinyfd_silent = 1;
int tinyfd_allowCursesDialogs = 0;
int tinyfd_forceConsole = 0;
int tinyfd_assumeGraphicDisplay = 0;
int tinyfd_winUtf8 = 1;
char tinyfd_response[1024] = "";
char const tinyfd_version[8] = "3.18.2";
char const tinyfd_needs[] = "browser";

static void log_dialog(const char* title, const char* message) {
#ifdef __EMSCRIPTEN__
    EM_ASM({
        console.log('[dialog] ' + (UTF8ToString($0) || '') + ': ' + (UTF8ToString($1) || ''));
    }, title ? title : "", message ? message : "");
#else
    fprintf(stderr, "[dialog] %s: %s\n", title ? title : "", message ? message : "");
#endif
}

int tinyfd_notifyPopup(char const* aTitle, char const* aMessage, char const* aIconType) {
    (void)aIconType;
    log_dialog(aTitle, aMessage);
    return 1;
}

int tinyfd_messageBox(char const* aTitle, char const* aMessage, char const* aDialogType,
                      char const* aIconType, int aDefaultButton) {
    (void)aDialogType;
    (void)aIconType;
    log_dialog(aTitle, aMessage);
    /* Return the caller's default button. Every confirmation site in the app
     * passes 0 (cancel/no), so destructive "okcancel"/"yesno" prompts default
     * to the safe, non-destructive choice in the browser build. */
    return aDefaultButton;
}

char* tinyfd_inputBox(char const* aTitle, char const* aMessage, char const* aDefaultInput) {
    (void)aTitle;
    (void)aMessage;
    (void)aDefaultInput;
    return (char*)0; /* cancelled */
}

char* tinyfd_saveFileDialog(char const* aTitle, char const* aDefaultPathAndOrFile,
                            int aNumOfFilterPatterns, char const* const* aFilterPatterns,
                            char const* aSingleFilterDescription) {
    (void)aTitle;
    (void)aDefaultPathAndOrFile;
    (void)aNumOfFilterPatterns;
    (void)aFilterPatterns;
    (void)aSingleFilterDescription;
    return (char*)0;
}

char* tinyfd_openFileDialog(char const* aTitle, char const* aDefaultPathAndOrFile,
                            int aNumOfFilterPatterns, char const* const* aFilterPatterns,
                            char const* aSingleFilterDescription, int aAllowMultipleSelects) {
    (void)aTitle;
    (void)aDefaultPathAndOrFile;
    (void)aNumOfFilterPatterns;
    (void)aFilterPatterns;
    (void)aSingleFilterDescription;
    (void)aAllowMultipleSelects;
    return (char*)0;
}

char* tinyfd_selectFolderDialog(char const* aTitle, char const* aDefaultPath) {
    (void)aTitle;
    (void)aDefaultPath;
    return (char*)0;
}

char* tinyfd_colorChooser(char const* aTitle, char const* aDefaultHexRGB,
                          unsigned char const aDefaultRGB[3], unsigned char aoResultRGB[3]) {
    (void)aTitle;
    (void)aDefaultHexRGB;
    if (aoResultRGB && aDefaultRGB) {
        aoResultRGB[0] = aDefaultRGB[0];
        aoResultRGB[1] = aDefaultRGB[1];
        aoResultRGB[2] = aDefaultRGB[2];
    }
    return (char*)0;
}
