#include "client/d3d11_overlay.h"

#include "client/game_hooks.h"
#include "common/diagnostics.h"

#include <MinHook.h>
#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <d3d11.h>
#include <dxgi.h>
#include <imgui.h>
#include <imgui_impl_dx11.h>
#include <imgui_impl_win32.h>

namespace client::overlay {

namespace {

using CreateDeviceAndSwapChain = HRESULT(WINAPI*)(IDXGIAdapter*, D3D_DRIVER_TYPE, HMODULE, UINT,
                                                  const D3D_FEATURE_LEVEL*, UINT, UINT, const DXGI_SWAP_CHAIN_DESC*,
                                                  IDXGISwapChain**, ID3D11Device**, D3D_FEATURE_LEVEL*,
                                                  ID3D11DeviceContext**);
using Present = HRESULT(STDMETHODCALLTYPE*)(IDXGISwapChain*, UINT, UINT);

CreateDeviceAndSwapChain original_create_device = nullptr;
Present original_present = nullptr;
ID3D11Device* device = nullptr;
ID3D11DeviceContext* context = nullptr;
ID3D11RenderTargetView* render_target = nullptr;
HWND game_window = nullptr;
bool initialized = false;
bool visible = true;
bool previous_toggle_state = false;
std::atomic_bool installed = false;

void initialize_imgui(IDXGISwapChain* swap_chain) {
    // Creates the ImGui context and render target from the first valid game swap chain.
    DXGI_SWAP_CHAIN_DESC description{};
    if (swap_chain == nullptr || FAILED(swap_chain->GetDesc(&description))) {
        launcher::diagnostics::show_error(L"Client", L"The Direct3D 11 swap-chain description is unavailable.",
                                          L"Update the client for the active GTA V renderer configuration.");
        return;
    }
    game_window = description.OutputWindow;
    if (FAILED(swap_chain->GetDevice(__uuidof(ID3D11Device), reinterpret_cast<void**>(&device)))) {
        launcher::diagnostics::show_error(
            L"Client", L"The Direct3D 11 device could not be retrieved.",
            L"Ensure GTA V is running with Direct3D 11 and disable incompatible overlays.");
        return;
    }
    device->GetImmediateContext(&context);
    ID3D11Texture2D* back_buffer = nullptr;
    if (SUCCEEDED(swap_chain->GetBuffer(0, __uuidof(ID3D11Texture2D), reinterpret_cast<void**>(&back_buffer)))) {
        device->CreateRenderTargetView(back_buffer, nullptr, &render_target);
        back_buffer->Release();
    }
    ImGui::CreateContext();
    ImGui::StyleColorsDark();
    if (!ImGui_ImplWin32_Init(game_window) || !ImGui_ImplDX11_Init(device, context)) {
        launcher::diagnostics::show_error(
            L"Client", L"ImGui could not initialize its Win32 or Direct3D 11 backend.",
            L"Keep the ImGui runtime compatible with the built Client.dll and use Direct3D 11.");
        return;
    }
    initialized = render_target != nullptr;
}

HRESULT STDMETHODCALLTYPE present_hook(IDXGISwapChain* swap_chain, const UINT sync_interval, const UINT flags) {
    // Draws the diagnostic overlay once per frame before calling the original Present method.
    if (!initialized) {
        initialize_imgui(swap_chain);
    }
    const bool toggle_pressed = (GetAsyncKeyState(VK_F4) & 0x8000) != 0;
    if (toggle_pressed && !previous_toggle_state) {
        visible = !visible;
    }
    previous_toggle_state = toggle_pressed;

    if (initialized && visible) {
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        ImGui::SetNextWindowSize(ImVec2(430.0F, 190.0F), ImGuiCond_FirstUseEver);
        ImGui::Begin("GTA Launcher", &visible, ImGuiWindowFlags_NoCollapse);
        ImGui::TextUnformatted("Standalone client DLL");
        ImGui::Separator();
        ImGui::Text("Process: GTA5.exe (PID %lu)", GetCurrentProcessId());
        ImGui::Text("Game hooks installed: %zu", game::installed_count());
        ImGui::Text("Renderer: Direct3D 11");
        ImGui::TextUnformatted("F4 toggles this window");
        ImGui::End();
        ImGui::Render();
        context->OMSetRenderTargets(1, &render_target, nullptr);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    }
    return original_present(swap_chain, sync_interval, flags);
}

HRESULT WINAPI create_device_hook(IDXGIAdapter* adapter, const D3D_DRIVER_TYPE driver_type, HMODULE software,
                                  const UINT flags, const D3D_FEATURE_LEVEL* feature_levels, const UINT feature_count,
                                  const UINT sdk_version, const DXGI_SWAP_CHAIN_DESC* description,
                                  IDXGISwapChain** swap_chain, ID3D11Device** output_device,
                                  D3D_FEATURE_LEVEL* feature_level, ID3D11DeviceContext** output_context) {
    // Captures the first swap-chain vtable and redirects Present to the ImGui renderer.
    const HRESULT result =
        original_create_device(adapter, driver_type, software, flags, feature_levels, feature_count, sdk_version,
                               description, swap_chain, output_device, feature_level, output_context);
    if (SUCCEEDED(result) && swap_chain != nullptr && *swap_chain != nullptr) {
        auto** vtable = *reinterpret_cast<void***>(*swap_chain);
        DWORD protection = 0;
        if (!VirtualProtect(&vtable[8], sizeof(void*), PAGE_EXECUTE_READWRITE, &protection)) {
            launcher::diagnostics::show_error(
                L"Client", L"The Direct3D 11 Present vtable entry could not be made writable.",
                L"Disable anti-tamper or overlay software that protects the swap-chain vtable.", GetLastError());
            return result;
        }
        original_present = reinterpret_cast<Present>(vtable[8]);
        vtable[8] = reinterpret_cast<void*>(&present_hook);
        VirtualProtect(&vtable[8], sizeof(void*), protection, &protection);
    }
    return result;
}

} // namespace

void install() {
    // Hooks D3D11CreateDeviceAndSwapChain so the overlay can attach to GTA V's actual swap chain.
    HMODULE d3d11 = GetModuleHandleW(L"d3d11.dll");
    if (d3d11 == nullptr) {
        d3d11 = LoadLibraryW(L"d3d11.dll");
    }
    if (d3d11 == nullptr) {
        launcher::diagnostics::show_error(L"Client", L"d3d11.dll could not be loaded.",
                                          L"Install or repair the DirectX 11 runtime and start GTA V again.",
                                          GetLastError());
        return;
    }
    auto* exported = GetProcAddress(d3d11, "D3D11CreateDeviceAndSwapChain");
    if (exported == nullptr ||
        MH_CreateHook(exported, reinterpret_cast<void*>(&create_device_hook),
                      reinterpret_cast<void**>(&original_create_device)) != MH_OK ||
        MH_EnableHook(exported) != MH_OK) {
        launcher::diagnostics::show_error(L"Client", L"The Direct3D 11 device creation hook could not be installed.",
                                          L"Use the x64 client build and disable conflicting graphics overlays.");
        return;
    }
    installed = true;
}

void remove() {
    // Releases the renderer resources and disables the overlay hook during controlled shutdown.
    if (!installed) {
        return;
    }
    MH_DisableHook(MH_ALL_HOOKS);
    if (initialized) {
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();
    }
    if (render_target != nullptr) {
        render_target->Release();
    }
    if (context != nullptr) {
        context->Release();
    }
    if (device != nullptr) {
        device->Release();
    }
    installed = false;
}

} // namespace client::overlay
