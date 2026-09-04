#include "common/remote_library.h"

#include "common/diagnostics.h"

#include <string>

namespace launcher::process {

bool inject_library(const HANDLE process, const std::wstring_view library_path) {
    // Injects a DLL by writing its path into the target and running LoadLibraryW there.
    launcher::diagnostics::log(L"INFO", L"Injection", L"Starting remote DLL injection: " + std::wstring(library_path));
    if (process == nullptr || library_path.empty()) {
        SetLastError(ERROR_INVALID_PARAMETER);
        launcher::diagnostics::log(L"ERROR", L"Injection", L"Invalid process handle or empty library path.",
                                   ERROR_INVALID_PARAMETER);
        return false;
    }

    const auto bytes = (library_path.size() + 1U) * sizeof(wchar_t);
    void* remote_path = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote_path == nullptr) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        launcher::diagnostics::log(L"ERROR", L"Injection", L"VirtualAllocEx failed.", ERROR_NOT_ENOUGH_MEMORY);
        return false;
    }

    SIZE_T written = 0;
    const bool copied = WriteProcessMemory(process, remote_path, library_path.data(), bytes, &written) != FALSE;
    if (!copied || written != bytes) {
        const DWORD error = copied ? ERROR_PARTIAL_COPY : GetLastError();
        VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
        SetLastError(error);
        launcher::diagnostics::log(L"ERROR", L"Injection", L"WriteProcessMemory failed.", error);
        return false;
    }
    const auto load_library =
        reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));
    HANDLE thread = nullptr;
    if (load_library != nullptr) {
        thread = CreateRemoteThread(process, nullptr, 0, load_library, remote_path, 0, nullptr);
    }

    bool success = false;
    DWORD failure_error = ERROR_SUCCESS;
    if (thread != nullptr) {
        const DWORD wait_result = WaitForSingleObject(thread, 15'000);
        if (wait_result == WAIT_TIMEOUT) {
            failure_error = ERROR_TIMEOUT;
            SetLastError(failure_error);
        } else if (wait_result == WAIT_FAILED) {
            failure_error = GetLastError();
        }
        success = wait_result == WAIT_OBJECT_0;
        DWORD exit_code = 0;
        if (success && GetExitCodeThread(thread, &exit_code) == FALSE) {
            failure_error = GetLastError();
            SetLastError(failure_error);
            success = false;
        } else if (success && exit_code == 0) {
            // LoadLibraryW returns NULL when a dependency, architecture, or DllMain check fails.
            failure_error = ERROR_DLL_INIT_FAILED;
            SetLastError(failure_error);
            success = false;
        }
        CloseHandle(thread);
    } else {
        failure_error = ERROR_PROC_NOT_FOUND;
        SetLastError(failure_error);
        launcher::diagnostics::log(L"ERROR", L"Injection", L"CreateRemoteThread could not be created.",
                                   ERROR_PROC_NOT_FOUND);
    }
    VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
    launcher::diagnostics::log(success ? L"INFO" : L"ERROR", L"Injection",
                               success ? L"Remote DLL injection completed." : L"Remote DLL injection failed.",
                               success ? ERROR_SUCCESS : failure_error);
    return success;
}

bool is_executable_name(const std::wstring_view path, const std::wstring_view expected_name) {
    // Compares an application path or a quoted command line with an executable name.
    std::wstring command(path);
    const auto first_non_space = command.find_first_not_of(L" \t");
    if (first_non_space == std::wstring::npos) {
        return false;
    }
    command.erase(0, first_non_space);
    if (!command.empty() && command.front() == L'\"') {
        command.erase(0, 1);
        const auto closing_quote = command.find(L'\"');
        command.resize(closing_quote == std::wstring::npos ? command.size() : closing_quote);
    } else {
        const auto argument = command.find_first_of(L" \t");
        command.resize(argument == std::wstring::npos ? command.size() : argument);
    }
    const auto slash = command.find_last_of(L"\\/");
    const std::wstring name = command.substr(slash == std::wstring::npos ? 0 : slash + 1);
    return _wcsicmp(name.c_str(), std::wstring(expected_name).c_str()) == 0;
}

} // namespace launcher::process
