#include "client/d3d11_overlay.h"
#include "client/game_hooks.h"
#include "client/python_runtime.h"
#include "common/diagnostics.h"

#include <MinHook.h>
#include <Windows.h>
#include <cwchar>

namespace {

HMODULE client_module = nullptr;

DWORD WINAPI initialize_client(void*) {
    // Install the renderer hook before scanning game signatures so GTA V cannot
    // create its swap chain before Present interception is active.
    launcher::diagnostics::log(L"INFO", L"Client", L"Client initialization worker started.");
    const MH_STATUS min_hook_status = MH_Initialize();
    if (min_hook_status != MH_OK && min_hook_status != MH_ERROR_ALREADY_INITIALIZED) {
        launcher::diagnostics::show_error(L"Client", L"MinHook could not be initialized.",
                                          L"Use the x64 client build and remove conflicting hook libraries.");
        return 0;
    }
    launcher::diagnostics::log(L"INFO", L"Client", L"MinHook initialized.");
    launcher::diagnostics::log(L"INFO", L"Client", L"Installing Direct3D 11 overlay hook.");
    client::overlay::install();
    launcher::diagnostics::log(L"INFO", L"Client", L"Installing game hooks.");
    client::game::install();
    launcher::diagnostics::log(L"INFO", L"Client", L"Initializing embedded Python runtime.");
    client::python::initialize();
    launcher::diagnostics::log(L"INFO", L"Client", L"Client initialization worker completed.");
    return 0;
}

} // namespace

BOOL APIENTRY DllMain(const HMODULE module, const DWORD reason, LPVOID) {
    // Keeps DLL entry lightweight and defers all game and renderer work to the Windows thread pool.
    if (reason == DLL_PROCESS_ATTACH) {
        client_module = module;
        DisableThreadLibraryCalls(module);
        launcher::diagnostics::log(L"INFO", L"Client", L"Client.dll attached to GTA5.exe.");
        if (QueueUserWorkItem(initialize_client, nullptr, WT_EXECUTEDEFAULT) == FALSE) {
            const DWORD error = GetLastError();
            wchar_t message[256]{};
            swprintf_s(message, L"[GtaLauncher][ERROR][Client] QueueUserWorkItem failed: %lu.\n", error);
            OutputDebugStringW(message);
            SetLastError(error);
            return FALSE;
        }
    }
    if (reason == DLL_PROCESS_DETACH) {
        client::python::shutdown();
    }
    return TRUE;
}
