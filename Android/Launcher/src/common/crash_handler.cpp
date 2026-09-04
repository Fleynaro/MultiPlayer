#include "common/crash_handler.h"

#include "common/diagnostics.h"

#include <DbgHelp.h>
#include <Windows.h>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>

#pragma comment(lib, "Dbghelp.lib")

namespace launcher::crash_handler {

namespace {

std::mutex handler_mutex;
std::wstring installed_component;
std::terminate_handler previous_terminate_handler = nullptr;
std::atomic_flag handling_crash = ATOMIC_FLAG_INIT;

std::filesystem::path module_directory() {
    std::wstring buffer(MAX_PATH, L'\0');
    DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length == 0) {
        return {};
    }
    buffer.resize(length);
    return std::filesystem::path(buffer).parent_path();
}

std::wstring timestamp() {
    const auto now = std::chrono::system_clock::now();
    const auto time = std::chrono::system_clock::to_time_t(now);
    tm local_time{};
    localtime_s(&local_time, &time);
    std::wstringstream result;
    result << std::put_time(&local_time, L"%Y%m%d-%H%M%S") << L"-" << GetCurrentProcessId();
    return result.str();
}

std::filesystem::path dump_path() {
    const auto directory = module_directory();
    if (directory.empty()) {
        return L"GtaLauncher-Crash.dmp";
    }
    std::error_code error;
    const auto dump_directory = directory / L"CrashDumps";
    std::filesystem::create_directories(dump_directory, error);
    return dump_directory / (L"GtaLauncher-" + timestamp() + L".dmp");
}

bool write_dump(EXCEPTION_POINTERS* exception_info, std::filesystem::path& path, DWORD& error_code) {
    path = dump_path();
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error_code = GetLastError();
        return false;
    }

    MINIDUMP_EXCEPTION_INFORMATION exception_data{
        .ThreadId = GetCurrentThreadId(), .ExceptionPointers = exception_info, .ClientPointers = FALSE};
    constexpr auto dump_type = static_cast<MINIDUMP_TYPE>(
        static_cast<unsigned long>(MiniDumpWithDataSegs) |
        static_cast<unsigned long>(MiniDumpWithIndirectlyReferencedMemory) |
        static_cast<unsigned long>(MiniDumpWithThreadInfo) | static_cast<unsigned long>(MiniDumpWithUnloadedModules));
    const bool written =
        MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), file, dump_type,
                          exception_info != nullptr ? &exception_data : nullptr, nullptr, nullptr) != FALSE;
    error_code = written ? ERROR_SUCCESS : GetLastError();
    CloseHandle(file);
    return written;
}

LONG WINAPI unhandled_exception(EXCEPTION_POINTERS* exception_info) {
    if (handling_crash.test_and_set()) {
        return EXCEPTION_EXECUTE_HANDLER;
    }

    const DWORD exception_code = exception_info != nullptr && exception_info->ExceptionRecord != nullptr
                                     ? exception_info->ExceptionRecord->ExceptionCode
                                     : ERROR_UNHANDLED_EXCEPTION;
    const ULONG_PTR exception_address =
        exception_info != nullptr && exception_info->ExceptionRecord != nullptr
            ? reinterpret_cast<ULONG_PTR>(exception_info->ExceptionRecord->ExceptionAddress)
            : 0;
    std::wstring component;
    {
        std::scoped_lock lock(handler_mutex);
        component = installed_component.empty() ? L"CrashHandler" : installed_component;
    }

    std::filesystem::path path;
    DWORD dump_error = ERROR_SUCCESS;
    const bool dump_written = write_dump(exception_info, path, dump_error);
    std::wstring message = L"Unhandled exception 0x";
    std::wstringstream details;
    details << std::hex << std::uppercase << exception_code << L" at 0x" << exception_address;
    message += details.str();
    message += dump_written ? L"; dump written to " : L"; dump could not be written: ";
    message += dump_written ? path.wstring() : diagnostics::win32_message(dump_error);
    diagnostics::log(L"FATAL", component, message, dump_written ? ERROR_SUCCESS : dump_error);

    return EXCEPTION_EXECUTE_HANDLER;
}

void terminate_handler() noexcept {
    try {
        unhandled_exception(nullptr);
        if (previous_terminate_handler != nullptr) {
            previous_terminate_handler();
        }
    } catch (...) {
        OutputDebugStringW(L"[GtaLauncher][FATAL][CrashHandler] Exception while writing crash dump.\n");
    }
    abort();
}

} // namespace

void install(const std::wstring_view component) {
    std::scoped_lock lock(handler_mutex);
    installed_component = component;
    SetUnhandledExceptionFilter(unhandled_exception);
    previous_terminate_handler = std::set_terminate(terminate_handler);
    diagnostics::log(L"INFO", installed_component, L"Crash handler installed.");
}

} // namespace launcher::crash_handler
