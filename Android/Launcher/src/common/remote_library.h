#pragma once

#include <Windows.h>
#include <string_view>

namespace launcher::process {

// Injects a DLL into a suspended or running process and preserves a Win32 error on failure.
[[nodiscard]] bool inject_library(HANDLE process, std::wstring_view library_path);

// Checks whether a path or command line identifies the requested executable.
[[nodiscard]] bool is_executable_name(std::wstring_view path, std::wstring_view expected_name);

} // namespace launcher::process
