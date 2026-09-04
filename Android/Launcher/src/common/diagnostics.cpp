#include "common/diagnostics.h"

#include <Windows.h>
#include <array>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>

namespace launcher::diagnostics {

namespace {

std::mutex log_mutex;

std::string utf8(const std::wstring_view value) {
    if (value.empty()) {
        return {};
    }
    const int size =
        WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        return "<text conversion failed>";
    }
    std::string result(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), size, nullptr,
                        nullptr);
    return result;
}

std::filesystem::path log_path() {
    HMODULE diagnostics_module = nullptr;
    const auto diagnostics_address = reinterpret_cast<LPCWSTR>(reinterpret_cast<std::uintptr_t>(&log));
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           diagnostics_address, &diagnostics_module) != FALSE) {
        std::wstring buffer(MAX_PATH, L'\0');
        const DWORD length = GetModuleFileNameW(diagnostics_module, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length != 0) {
            buffer.resize(length);
            return std::filesystem::path(buffer).parent_path() / L"GtaLauncher.log";
        }
    }

    std::wstring buffer(MAX_PATH, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length == 0) {
        return L"GtaLauncher.log";
    }
    buffer.resize(length);
    return std::filesystem::path(buffer).parent_path() / L"GtaLauncher.log";
}

std::ofstream open_log_file() {
    std::ofstream file(log_path(), std::ios::app);
    if (file.is_open()) {
        return file;
    }

    wchar_t temporary_directory[MAX_PATH]{};
    const DWORD length = GetTempPathW(static_cast<DWORD>(std::size(temporary_directory)), temporary_directory);
    if (length != 0 && length < std::size(temporary_directory)) {
        file.open(std::filesystem::path(temporary_directory) / L"GtaLauncher.log", std::ios::app);
    }
    return file;
}

} // namespace

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

void log(const std::wstring_view level, const std::wstring_view component, const std::wstring_view message,
         const DWORD error_code) {
    std::scoped_lock lock(log_mutex);
    const auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    tm local_time{};
    localtime_s(&local_time, &now);
    std::array<char, 32> timestamp{};
    strftime(timestamp.data(), timestamp.size(), "%Y-%m-%d %H:%M:%S", &local_time);

    std::wstring full_message = std::wstring(message);
    if (error_code != ERROR_SUCCESS) {
        full_message += L" | Windows error " + std::to_wstring(error_code) + L": " + win32_message(error_code);
    }
    const std::string line = "[" + std::string(timestamp.data()) + "][PID " + std::to_string(GetCurrentProcessId()) +
                             "][" + utf8(level) + "][" + utf8(component) + "] " + utf8(full_message) + "\n";
    OutputDebugStringW(
        (L"[GtaLauncher][" + std::wstring(level) + L"][" + std::wstring(component) + L"] " + full_message + L"\n")
            .c_str());
    std::ofstream file = open_log_file();
    if (file.is_open()) {
        file << line;
        file.flush();
    } else {
        OutputDebugStringW(L"[GtaLauncher][ERROR][Diagnostics] Could not open GtaLauncher.log.\n");
    }
}

// Builds one consistent English diagnostic for both the user and the debugger.
void show_error(const std::wstring_view component, const std::wstring_view problem, const std::wstring_view solution,
                const DWORD error_code) {
    const std::wstring base_message = std::wstring(problem) + L"\n\nRequired action:\n" + std::wstring(solution);
    std::wstring message = base_message;
    if (error_code != ERROR_SUCCESS) {
        message += L"\n\nWindows error " + std::to_wstring(error_code) + L": " + win32_message(error_code);
    }
    log(L"ERROR", component, base_message, error_code);
    MessageBoxW(nullptr, message.c_str(), (L"GTA Launcher - " + std::wstring(component)).c_str(),
                MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
}

// Builds one consistent English warning for recoverable runtime problems.
void show_warning(const std::wstring_view component, const std::wstring_view problem,
                  const std::wstring_view solution) {
    const std::wstring message = std::wstring(problem) + L"\n\nRecommended action:\n" + std::wstring(solution);
    log(L"WARNING", component, message);
    MessageBoxW(nullptr, message.c_str(), (L"GTA Launcher - " + std::wstring(component)).c_str(),
                MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL);
}

} // namespace launcher::diagnostics
