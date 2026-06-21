#ifndef ZATHURA_UI_SAFEDIALOGS_HPP
#define ZATHURA_UI_SAFEDIALOGS_HPP

#include <string>
#include <tinyfiledialogs.h>

// tinyfiledialogs refuses to display any title/message containing characters it
// treats as shell-dangerous (see tfd_quoteDetected in tinyfiledialogs.c): a
// single quote ('), double quote ("), backtick (`), or a '$' that begins a
// shell expansion. When one is present it silently substitutes the literal text
// "INVALID MESSAGE WITH QUOTES", hiding the real message from the user.
//
// These wrappers sanitize user-facing strings by swapping those ASCII
// characters for visually-equivalent Unicode glyphs that tinyfiledialogs
// accepts, so the intended text is always shown -- including dynamic content
// such as file names that may legitimately contain quotes. Encoded as explicit
// UTF-8 bytes to stay independent of the compiler's execution charset.

namespace Zathura {

inline std::string sanitizeForTinyfd(const char* text) {
    std::string out;
    if (text == nullptr) {
        return out;
    }
    for (const char* p = text; *p != '\0'; ++p) {
        switch (*p) {
            case '\'': out += "\xE2\x80\x99"; break; // U+2019 right single quote
            case '"':  out += "\xE2\x80\x9D"; break; // U+201D right double quote
            case '`':  out += "\xE2\x80\x98"; break; // U+2018 left single quote
            case '$':  out += "\xEF\xBC\x84"; break; // U+FF04 fullwidth dollar
            default:   out += *p;             break;
        }
    }
    return out;
}

inline int safeMessageBox(const char* title, const char* message,
                          const char* dialogType, const char* iconType,
                          const int defaultButton) {
    const std::string safeTitle = sanitizeForTinyfd(title);
    const std::string safeMessage = sanitizeForTinyfd(message);
    return tinyfd_messageBox(safeTitle.c_str(), safeMessage.c_str(),
                             dialogType, iconType, defaultButton);
}

inline int safeNotifyPopup(const char* title, const char* message,
                           const char* iconType) {
    const std::string safeTitle = sanitizeForTinyfd(title);
    const std::string safeMessage = sanitizeForTinyfd(message);
    return tinyfd_notifyPopup(safeTitle.c_str(), safeMessage.c_str(), iconType);
}

inline const char* safeInputBox(const char* title, const char* message,
                                const char* defaultInput) {
    const std::string safeTitle = sanitizeForTinyfd(title);
    const std::string safeMessage = sanitizeForTinyfd(message);
    // A NULL defaultInput requests a hidden password field; preserve that.
    if (defaultInput == nullptr) {
        return tinyfd_inputBox(safeTitle.c_str(), safeMessage.c_str(), nullptr);
    }
    const std::string safeDefault = sanitizeForTinyfd(defaultInput);
    return tinyfd_inputBox(safeTitle.c_str(), safeMessage.c_str(),
                           safeDefault.c_str());
}

} // namespace Zathura

#endif // ZATHURA_UI_SAFEDIALOGS_HPP
