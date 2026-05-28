#ifndef ZATHURA_PCH_HPP
#define ZATHURA_PCH_HPP

// STL headers used across many TUs
#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <stack>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// Stable vendor headers (rarely change, expensive to parse)
#define IMGUI_DEFINE_MATH_OPERATORS
#include "../vendor/imgui/imgui.h"
#include "../vendor/imgui/imgui_internal.h"
#include "../vendor/imgui/backends/imgui_impl_glfw.h"
#include "../vendor/imgui/backends/imgui_impl_opengl3.h"
#include "../vendor/imgui/misc/cpp/imgui_stdlib.h"

#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <keystone/keystone.h>

#include <tsl/ordered_map.h>
#include "../vendor/ImGuiColorTextEdit/TextEditor.h"

#endif // ZATHURA_PCH_HPP
