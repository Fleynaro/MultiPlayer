#include "common/diagnostics.h"
#include "common/remote_library.h"

#include <MinHook.h>
#include <Windows.h>
#include <cwchar>
#include <filesystem>
#include <string>

namespace {

using CreateProcessWFunction = BOOL(WINAPI*)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD,
                                             LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
using CreateProcessAFunction = BOOL(WINAPI*)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD,
                                             LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
CreateProcessWFunction original_create_process = nullptr;
CreateProcessAFunction original_create_process_a = nullptr;
HMODULE module_handle = nullptr;

std::filesystem::path module_directory() {
    // Returns the directory containing Bootstrap.dll for locating Client.dll.
    std::wstring buffer(MAX_PATH, L'\0');
    const DWORD length = GetModuleFileNameW(module_handle, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length == 0) {
        launcher::diagnostics::show_error(L"Bootstrap", L"The Bootstrap.dll module path could not be determined.",
                                          L"Keep Bootstrap.dll in a local directory beside Client.dll.",
                                          GetLastError());
        return {};
    }
    buffer.resize(length);
    return std::filesystem::path(buffer).parent_path();
}

BOOL WINAPI create_process_hook(LPCWSTR application_name, LPWSTR command_line, LPSECURITY_ATTRIBUTES process_attributes,
                                LPSECURITY_ATTRIBUTES thread_attributes, const BOOL inherit_handles,
                                const DWORD creation_flags, LPVOID environment, LPCWSTR current_directory,
                                LPSTARTUPINFOW startup_info, LPPROCESS_INFORMATION process_information) {
    // Forces GTA5.exe to remain suspended long enough for Client.dll to be injected.
    const std::wstring_view executable = application_name != nullptr
                                             ? std::wstring_view(application_name)
                                             : std::wstring_view(command_line != nullptr ? command_line : L"");
    const bool is_game = launcher::process::is_executable_name(executable, L"GTA5.exe");
    launcher::diagnostics::log(L"INFO", L"Bootstrap",
                               is_game ? L"Intercepted GTA5.exe process creation (Unicode path)."
                                       : L"Intercepted non-game process creation (Unicode path).");
    const DWORD flags = is_game ? creation_flags | CREATE_SUSPENDED : creation_flags;
    if (!original_create_process(application_name, command_line, process_attributes, thread_attributes, inherit_handles,
                                 flags, environment, current_directory, startup_info, process_information)) {
        launcher::diagnostics::show_error(L"Bootstrap", L"The launcher failed to create GTA5.exe.",
                                          L"Close GTA V, verify the game installation, and start Launcher.exe again.",
                                          GetLastError());
        return FALSE;
    }

    if (!is_game) {
        return TRUE;
    }

    const auto bootstrap_directory = module_directory();
    if (bootstrap_directory.empty()) {
        TerminateProcess(process_information->hProcess, ERROR_PATH_NOT_FOUND);
        CloseHandle(process_information->hThread);
        CloseHandle(process_information->hProcess);
        SetLastError(ERROR_PATH_NOT_FOUND);
        return FALSE;
    }
    const auto client = bootstrap_directory / L"Client.dll";
    if (!std::filesystem::is_regular_file(client)) {
        launcher::diagnostics::show_error(L"Bootstrap", L"Client.dll is missing beside Bootstrap.dll.",
                                          L"Build the project and place Client.dll beside Bootstrap.dll.");
        TerminateProcess(process_information->hProcess, ERROR_FILE_NOT_FOUND);
        CloseHandle(process_information->hThread);
        CloseHandle(process_information->hProcess);
        SetLastError(ERROR_FILE_NOT_FOUND);
        return FALSE;
    }
    if (!launcher::process::inject_library(process_information->hProcess, client.wstring())) {
        const DWORD error = GetLastError();
        launcher::diagnostics::show_error(L"Bootstrap", L"Client.dll could not be injected into GTA5.exe.",
                                          L"Run Launcher.exe as administrator, disable conflicting overlays, and "
                                          L"verify that Client.dll matches the build.",
                                          error);
        TerminateProcess(process_information->hProcess, ERROR_DLL_INIT_FAILED);
        CloseHandle(process_information->hThread);
        CloseHandle(process_information->hProcess);
        SetLastError(ERROR_DLL_INIT_FAILED);
        return FALSE;
    }
    launcher::diagnostics::log(L"INFO", L"Bootstrap", L"Client.dll injection into GTA5.exe succeeded.");
    if (ResumeThread(process_information->hThread) == static_cast<DWORD>(-1)) {
        const DWORD error = GetLastError();
        launcher::diagnostics::show_error(L"Bootstrap", L"The GTA5.exe main thread could not be resumed.",
                                          L"Run as administrator and close debuggers or process protection software.",
                                          error);
        TerminateProcess(process_information->hProcess, ERROR_OPERATION_ABORTED);
        SetLastError(error);
        return FALSE;
    }
    return TRUE;
}

BOOL WINAPI create_process_a_hook(LPCSTR application_name, LPSTR command_line, LPSECURITY_ATTRIBUTES process_attributes,
                                  LPSECURITY_ATTRIBUTES thread_attributes, const BOOL inherit_handles,
                                  const DWORD creation_flags, LPVOID environment, LPCSTR current_directory,
                                  LPSTARTUPINFOA startup_info, LPPROCESS_INFORMATION process_information) {
    // Mirrors the legacy loader's CreateProcessA path for launchers that use ANSI Windows APIs.
    const std::string executable = application_name != nullptr
                                       ? std::string(application_name)
                                       : std::string(command_line != nullptr ? command_line : "");
    const auto separator = executable.find_first_of(" \t");
    const auto command_name = executable.substr(0, separator);
    const auto slash = command_name.find_last_of("\\/");
    const auto file_name = command_name.substr(slash == std::string::npos ? 0 : slash + 1);
    const bool is_game = _stricmp(file_name.c_str(), "GTA5.exe") == 0;
    launcher::diagnostics::log(L"INFO", L"Bootstrap",
                               is_game ? L"Intercepted GTA5.exe process creation (ANSI path)."
                                       : L"Intercepted non-game process creation (ANSI path).");
    const DWORD flags = is_game ? creation_flags | CREATE_SUSPENDED : creation_flags;
    if (!original_create_process_a(application_name, command_line, process_attributes, thread_attributes,
                                   inherit_handles, flags, environment, current_directory, startup_info,
                                   process_information)) {
        launcher::diagnostics::show_error(L"Bootstrap", L"The launcher failed to create GTA5.exe.",
                                          L"Close GTA V, verify the game installation, and start Launcher.exe again.",
                                          GetLastError());
        return FALSE;
    }
    if (!is_game) {
        return TRUE;
    }
    const auto client = module_directory() / L"Client.dll";
    if (!std::filesystem::is_regular_file(client) ||
        !launcher::process::inject_library(process_information->hProcess, client.wstring())) {
        const DWORD error = GetLastError();
        launcher::diagnostics::show_error(
            L"Bootstrap", L"Client.dll could not be injected into GTA5.exe.",
            L"Keep Client.dll beside Bootstrap.dll, use the static vcpkg build, and run as administrator.", error);
        TerminateProcess(process_information->hProcess, ERROR_DLL_INIT_FAILED);
        return FALSE;
    }
    if (ResumeThread(process_information->hThread) == static_cast<DWORD>(-1)) {
        launcher::diagnostics::show_error(L"Bootstrap", L"The GTA5.exe main thread could not be resumed.",
                                          L"Close debuggers and process protection software, then try again.",
                                          GetLastError());
        TerminateProcess(process_information->hProcess, ERROR_OPERATION_ABORTED);
        return FALSE;
    }
    return TRUE;
}

} // namespace

BOOL APIENTRY DllMain(const HMODULE module, const DWORD reason, LPVOID) {
    // Matches the legacy loader by installing MinHook directly during DLL attach.
    if (reason == DLL_PROCESS_ATTACH) {
        module_handle = module;
        DisableThreadLibraryCalls(module);
        launcher::diagnostics::log(L"INFO", L"Bootstrap", L"Bootstrap.dll attached to the launcher process.");
        if (MH_Initialize() != MH_OK ||
            MH_CreateHookApi(L"kernel32.dll", "CreateProcessA", &create_process_a_hook,
                             reinterpret_cast<void**>(&original_create_process_a)) != MH_OK ||
            MH_CreateHookApi(L"kernel32.dll", "CreateProcessW", &create_process_hook,
                             reinterpret_cast<void**>(&original_create_process)) != MH_OK ||
            MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
            launcher::diagnostics::show_error(L"Bootstrap",
                                              L"MinHook could not install the CreateProcessA/CreateProcessW hooks.",
                                              L"Use the x64 static-vcpkg build and close other hook managers.");
            MH_Uninitialize();
            return FALSE;
        }
        launcher::diagnostics::log(L"INFO", L"Bootstrap", L"CreateProcessA/CreateProcessW hooks installed.");
    }
    return TRUE;
}
