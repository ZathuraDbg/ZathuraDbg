#ifndef UIELEMENTS_H
#define UIELEMENTS_H
#define IMGUI_DEFINE_MATH_OPERATORS
#include "../../vendor/imgui/imgui_internal.h"
#include "../../vendor/imgui/imgui.h"
#include <string>
#include <cstdint>
#include <format>

extern bool InputHexadecimal(const char *label, void *value, const ImGuiInputTextFlags flags);
extern bool InputIntegerPrefix(const char *label, const char *prefix, void *value, ImGuiDataType type, const char *format, ImGuiInputTextFlags flags);
#endif //UIELEMENTS_H
