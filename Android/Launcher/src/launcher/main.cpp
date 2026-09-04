#include "common/config.h"
#include "common/diagnostics.h"
#include "common/remote_library.h"

#include <Windows.h>
#include <filesystem>
#include <string>

namespace {

std::filesystem::path module_directory() {
    // Returns the directory containing Launcher.exe so sibling DLLs can be located reliably.
    std::wstring buffer(MAX_PATH, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length == 0) {
        launcher::diagnostics::show_error(L"Launcher", L"The launcher module path could not be determined.",
                                          L"Start Launcher.exe from a local, accessible directory.", GetLastError());
        return {};
    }
    buffer.resize(length);
    return std::filesystem::path(buffer).parent_path();
}

bool enable_debug_privilege() {
    // Requests SeDebugPrivilege, which is needed when the target process has a different security level.
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        launcher::diagnostics::show_warning(L"Launcher", L"Debug privilege could not be requested.",
                                            L"Run the launcher as administrator if injection later fails.");
        return false;
    }
    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    const bool found = LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &privileges.Privileges[0].Luid) != FALSE;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    const bool enabled =
        found && AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr) != FALSE;
    CloseHandle(token);
    if (!enabled || GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        launcher::diagnostics::show_warning(L"Launcher", L"Windows did not grant SeDebugPrivilege.",
                                            L"Run Launcher.exe as administrator, then try again.");
        return false;
    }
    return true;
}

} // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    // Starts the two-stage injection chain after validating every required local file.
    launcher::diagnostics::log(L"INFO", L"Launcher", L"Launcher startup began.");
    enable_debug_privilege();
    const auto launcher_directory = module_directory();
    if (launcher_directory.empty()) {
        return ERROR_PATH_NOT_FOUND;
    }
    const auto settings = launcher::config::load(launcher_directory);
    wchar_t install_buffer[MAX_PATH]{};
    const DWORD length = GetEnvironmentVariableW(L"GTA_5_INSTALL_DIR", install_buffer, MAX_PATH);
    std::filesystem::path install_directory = settings.game_install_directory;
    if (install_directory.empty() && length == 0) {
        const DWORD error = GetLastError();
        launcher::diagnostics::show_error(
            L"Launcher", L"The GTA_5_INSTALL_DIR environment variable is missing or empty.",
            L"Set GTA_5_INSTALL_DIR to the folder containing GTAVLauncher.exe, then restart Launcher.exe.",
            error == ERROR_ENVVAR_NOT_FOUND ? ERROR_ENVVAR_NOT_FOUND : ERROR_INVALID_DATA);
        return error == ERROR_ENVVAR_NOT_FOUND ? ERROR_ENVVAR_NOT_FOUND : ERROR_INVALID_DATA;
    }
    if (install_directory.empty() && length >= MAX_PATH) {
        launcher::diagnostics::show_error(L"Launcher", L"GTA_5_INSTALL_DIR is too long for this launcher.",
                                          L"Use a shorter GTA V installation path.");
        return ERROR_BUFFER_OVERFLOW;
    }
    if (install_directory.empty()) {
        install_directory = install_buffer;
    }
    const auto game_launcher = install_directory / L"GTAVLauncher.exe";
    const auto bootstrap = launcher_directory / L"Bootstrap.dll";
    std::error_code filesystem_error;
    if (!std::filesystem::is_directory(install_directory, filesystem_error) ||
        !std::filesystem::is_regular_file(game_launcher, filesystem_error)) {
        launcher::diagnostics::show_error(
            L"Launcher", L"GTAVLauncher.exe was not found in GTA_5_INSTALL_DIR.",
            L"Correct GTA_5_INSTALL_DIR so it points directly to the GTA V installation directory.");
        return ERROR_FILE_NOT_FOUND;
    }
    filesystem_error.clear();
    if (!std::filesystem::is_regular_file(bootstrap, filesystem_error)) {
        launcher::diagnostics::show_error(
            L"Launcher", L"Bootstrap.dll is missing beside Launcher.exe.",
            L"Build the Android/Launcher project and keep Launcher.exe and Bootstrap.dll in the same directory.");
        return ERROR_FILE_NOT_FOUND;
    }

    launcher::diagnostics::log(L"INFO", L"Launcher",
                               L"Validated GTA_5_INSTALL_DIR, GTAVLauncher.exe, and Bootstrap.dll.");

    std::wstring command_line = L"\"" + game_launcher.wstring() + L"\"";
    STARTUPINFOW startup{.cb = sizeof(startup)};
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(game_launcher.c_str(), command_line.data(), nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr,
                        install_directory.c_str(), &startup, &process)) {
        const DWORD error = GetLastError();
        launcher::diagnostics::show_error(
            L"Launcher", L"GTAVLauncher.exe could not be started.",
            L"Close existing GTA V processes and verify that the installation is accessible.", error);
        return static_cast<int>(error);
    }
    launcher::diagnostics::log(L"INFO", L"Launcher", L"GTAVLauncher.exe started suspended.");

    const bool injected = launcher::process::inject_library(process.hProcess, bootstrap.wstring());
    if (!injected) {
        const DWORD error = GetLastError();
        TerminateProcess(process.hProcess, ERROR_DLL_INIT_FAILED);
        launcher::diagnostics::show_error(L"Launcher", L"Bootstrap.dll could not be injected into GTAVLauncher.exe.",
                                          L"Run as administrator, verify that security software allows the launcher, "
                                          L"and keep Bootstrap.dll beside Launcher.exe.",
                                          error);
    } else {
        launcher::diagnostics::log(L"INFO", L"Launcher", L"Bootstrap.dll injection succeeded.");
        if (ResumeThread(process.hThread) == static_cast<DWORD>(-1)) {
            launcher::diagnostics::show_error(
                L"Launcher", L"The GTA V launcher thread could not be resumed.",
                L"Run as administrator and ensure no debugger or security tool is suspending the process.",
                GetLastError());
            TerminateProcess(process.hProcess, ERROR_OPERATION_ABORTED);
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
            return ERROR_OPERATION_ABORTED;
        }
        launcher::diagnostics::log(L"INFO", L"Launcher", L"GTAVLauncher.exe resumed successfully.");
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return injected ? 0 : ERROR_DLL_INIT_FAILED;
}
