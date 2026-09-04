#include "client/d3d11_overlay.h"
#include "client/game_hooks.h"
#include "common/diagnostics.h"

#include <Windows.h>
#include <cwchar>

namespace {

HMODULE client_module = nullptr;

DWORD WINAPI initialize_client(void*) {
    // Waits for GTA V startup before touching game memory or Direct3D.
    launcher::diagnostics::log(L"INFO", L"Client", L"Client initialization worker started; waiting for GTA V startup.");
    Sleep(1500);
    launcher::diagnostics::log(L"INFO", L"Client", L"Installing game hooks.");
    client::game::install();
    launcher::diagnostics::log(L"INFO", L"Client", L"Installing Direct3D 11 overlay hook.");
    client::overlay::install();
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
    return TRUE;
}
