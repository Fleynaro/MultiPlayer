#include "common/diagnostics.h"

#include <string>

namespace launcher::diagnostics {

// Converts a system error code using the Windows message catalog.
std::wstring win32_message(const DWORD error_code) {
    if (error_code == ERROR_SUCCESS) {
        return L"No system error was reported.";
    }
    wchar_t* buffer = nullptr;
    const DWORD length =
        FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                       nullptr, error_code, 0, reinterpret_cast<wchar_t*>(&buffer), 0, nullptr);
    if (length == 0 || buffer == nullptr) {
        return L"Windows could not provide a description for error code " + std::to_wstring(error_code) + L".";
    }
    std::wstring message(buffer, length);
    LocalFree(buffer);
    while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n' || message.back() == L' ')) {
        message.pop_back();
    }
    return message;
}

// Builds one consistent English diagnostic for both the user and the debugger.
void show_error(const std::wstring_view component, const std::wstring_view problem, const std::wstring_view solution,
                const DWORD error_code) {
    std::wstring message = std::wstring(problem) + L"\n\nRequired action:\n" + std::wstring(solution);
    if (error_code != ERROR_SUCCESS) {
        message += L"\n\nWindows error " + std::to_wstring(error_code) + L": " + win32_message(error_code);
    }
    OutputDebugStringW(
        (std::wstring(L"[GtaLauncher][ERROR][") + std::wstring(component) + L"] " + message + L"\n").c_str());
    MessageBoxW(nullptr, message.c_str(), (L"GTA Launcher - " + std::wstring(component)).c_str(),
                MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
}

// Builds one consistent English warning for recoverable runtime problems.
void show_warning(const std::wstring_view component, const std::wstring_view problem,
                  const std::wstring_view solution) {
    const std::wstring message = std::wstring(problem) + L"\n\nRecommended action:\n" + std::wstring(solution);
    OutputDebugStringW(
        (std::wstring(L"[GtaLauncher][WARNING][") + std::wstring(component) + L"] " + message + L"\n").c_str());
    MessageBoxW(nullptr, message.c_str(), (L"GTA Launcher - " + std::wstring(component)).c_str(),
                MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL);
}

} // namespace launcher::diagnostics
