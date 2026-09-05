#include "common/crash_handler.h"

#include "common/diagnostics.h"

#include <DbgHelp.h>
#include <Windows.h>
#include <atomic>
#include <chrono>
#include <crtdbg.h>
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

constexpr DWORD fail_fast_exception = 0xC0000409;
std::mutex handler_mutex;
std::wstring installed_component;
std::terminate_handler previous_terminate_handler = nullptr;
std::atomic_flag handling_crash = ATOMIC_FLAG_INIT;
PVOID vectored_handler = nullptr;

std::filesystem::path module_directory() {
    // Resolve the module containing this function instead of the host process.
    // Client.dll is loaded into GTA5.exe, so GetModuleFileNameW(nullptr, ...)
    // would incorrectly place client dumps in the game installation directory.
    HMODULE crash_handler_module = nullptr;
    const auto handler_address = reinterpret_cast<LPCWSTR>(reinterpret_cast<std::uintptr_t>(&module_directory));
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           handler_address, &crash_handler_module) == FALSE) {
        return {};
    }

    std::wstring buffer(MAX_PATH, L'\0');
    DWORD length = GetModuleFileNameW(crash_handler_module, buffer.data(), static_cast<DWORD>(buffer.size()));
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

std::wstring exception_name(const DWORD exception_code) {
    switch (exception_code) {
        case EXCEPTION_ACCESS_VIOLATION:
            return L"Access violation";
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
            return L"Array bounds exceeded";
        case EXCEPTION_DATATYPE_MISALIGNMENT:
            return L"Datatype misalignment";
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:
            return L"Floating-point divide by zero";
        case EXCEPTION_ILLEGAL_INSTRUCTION:
            return L"Illegal instruction";
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
            return L"Integer divide by zero";
        case EXCEPTION_NONCONTINUABLE_EXCEPTION:
            return L"Non-continuable exception";
        case EXCEPTION_STACK_OVERFLOW:
            return L"Stack overflow";
        case fail_fast_exception:
            return L"Fail-fast exception";
        default:
            return L"Unknown Windows exception";
    }
}

std::wstring address_details(EXCEPTION_POINTERS* exception_info, const ULONG_PTR exception_address) {
    std::wstringstream details;
    details << L" at 0x" << std::hex << std::uppercase << exception_address;

    if (exception_info != nullptr && exception_info->ExceptionRecord != nullptr &&
        exception_info->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
        exception_info->ExceptionRecord->NumberParameters >= 2) {
        const ULONG_PTR operation = exception_info->ExceptionRecord->ExceptionInformation[0];
        const ULONG_PTR target = exception_info->ExceptionRecord->ExceptionInformation[1];
        const wchar_t* operation_name = operation == 0 ? L"read" : operation == 1 ? L"write" : L"execute";
        details << L" (" << operation_name << L" access at 0x" << std::hex << std::uppercase << target << L")";
    }

    HMODULE fault_module = nullptr;
    if (exception_address != 0 &&
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(exception_address), &fault_module) != FALSE) {
        std::wstring buffer(MAX_PATH, L'\0');
        const DWORD length = GetModuleFileNameW(fault_module, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length != 0) {
            buffer.resize(length);
            const auto module_path = std::filesystem::path(buffer);
            const auto module_base = reinterpret_cast<ULONG_PTR>(fault_module);
            details << L" in " << module_path.filename().wstring() << L"+0x" << std::hex << std::uppercase
                    << (exception_address - module_base);
        }
    }
    return details.str();
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

void report_fatal(const std::wstring_view reason, EXCEPTION_POINTERS* exception_info) noexcept {
    try {
        if (handling_crash.test_and_set()) {
            return;
        }

        std::wstring component;
        {
            std::scoped_lock lock(handler_mutex);
            component = installed_component.empty() ? L"CrashHandler" : installed_component;
        }

        std::filesystem::path path;
        DWORD dump_error = ERROR_SUCCESS;
        const bool dump_written = write_dump(exception_info, path, dump_error);
        std::wstring message(reason);
        message += dump_written ? L"; dump written to " : L"; dump could not be written: ";
        message += dump_written ? path.wstring() : diagnostics::win32_message(dump_error);
        diagnostics::log(L"FATAL", component, message, dump_written ? ERROR_SUCCESS : dump_error);
    } catch (...) {
        OutputDebugStringW(L"[GtaLauncher][FATAL][CrashHandler] Fatal report generation failed.\n");
    }
}

LONG WINAPI unhandled_exception(EXCEPTION_POINTERS* exception_info);

LONG WINAPI vectored_exception(EXCEPTION_POINTERS*) {
    // Reassert the last-chance handler if the game or security software replaced
    // it. The exception continues through normal Windows dispatch unchanged.
    SetUnhandledExceptionFilter(unhandled_exception);
    return EXCEPTION_CONTINUE_SEARCH;
}

LONG WINAPI unhandled_exception(EXCEPTION_POINTERS* exception_info) {
    const DWORD exception_code = exception_info != nullptr && exception_info->ExceptionRecord != nullptr
                                     ? exception_info->ExceptionRecord->ExceptionCode
                                     : ERROR_UNHANDLED_EXCEPTION;
    const ULONG_PTR exception_address =
        exception_info != nullptr && exception_info->ExceptionRecord != nullptr
            ? reinterpret_cast<ULONG_PTR>(exception_info->ExceptionRecord->ExceptionAddress)
            : 0;
    std::wstring message = L"Unhandled exception 0x";
    std::wstringstream details;
    details << std::hex << std::uppercase << exception_code;
    message += details.str() + L" (" + exception_name(exception_code) + L")";
    message += address_details(exception_info, exception_address);
    message += L"; thread " + std::to_wstring(GetCurrentThreadId());
    report_fatal(message, exception_info);

    return EXCEPTION_EXECUTE_HANDLER;
}

void invalid_parameter(const wchar_t*, const wchar_t*, const wchar_t*, unsigned, uintptr_t) noexcept {
    report_fatal(L"The C runtime reported an invalid parameter", nullptr);
    abort();
}

void purecall() noexcept {
    report_fatal(L"The C++ runtime reported a pure virtual function call", nullptr);
    abort();
}

void terminate_handler() noexcept {
    try {
        report_fatal(L"std::terminate was called", nullptr);
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
    if (vectored_handler == nullptr) {
        vectored_handler = AddVectoredExceptionHandler(1, vectored_exception);
    }
    SetUnhandledExceptionFilter(unhandled_exception);
    _set_invalid_parameter_handler(invalid_parameter);
    _set_purecall_handler(purecall);
    previous_terminate_handler = std::set_terminate(terminate_handler);
    diagnostics::log(L"INFO", installed_component,
                     vectored_handler != nullptr ? L"Crash handler installed (UEF, VEH, and CRT handlers)."
                                                 : L"Crash handler installed (UEF and CRT handlers; VEH unavailable).");
}

} // namespace launcher::crash_handler
