#pragma once

#include <Windows.h>
#include <string_view>

namespace launcher::diagnostics {

// Converts a Win32 error code into a readable English message.
[[nodiscard]] std::wstring win32_message(DWORD error_code);

// Shows a detailed actionable error to the user and writes it to the debugger.
void show_error(std::wstring_view component, std::wstring_view problem, std::wstring_view solution,
                DWORD error_code = ERROR_SUCCESS);

// Shows a detailed actionable warning without stopping the current process.
void show_warning(std::wstring_view component, std::wstring_view problem, std::wstring_view solution);

} // namespace launcher::diagnostics
