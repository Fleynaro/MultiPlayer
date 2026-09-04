#include "client/d3d11_overlay.h"

#include "client/game_hooks.h"
#include "client/python_runtime.h"
#include "common/config.h"
#include "common/diagnostics.h"

#include <MinHook.h>
#include <Windows.h>
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <d3d11.h>
#include <dxgi.h>
#include <imgui.h>
#include <imgui_impl_dx11.h>
#include <imgui_impl_win32.h>
#include <string>
#include <vector>

// The ImGui Win32 backend intentionally leaves this declaration disabled in its public header.
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND h_wnd, UINT message, WPARAM w_param, LPARAM l_param);

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
WNDPROC original_wnd_proc = nullptr;
bool initialized = false;
bool visible = true;
bool previous_toggle_state = false;
float ui_scale = 1.0F;
launcher::config::GuiSettings gui_settings;
std::atomic_bool installed = false;
int selected_script = 0;

LRESULT CALLBACK overlay_wnd_proc(const HWND window, const UINT message, const WPARAM w_param, const LPARAM l_param) {
    // Forward window messages to ImGui first so keyboard navigation and mouse controls work in the game window.
    if (initialized && window == game_window) {
        const LRESULT imgui_result = ImGui_ImplWin32_WndProcHandler(window, message, w_param, l_param);
        const ImGuiIO& io = ImGui::GetIO();
        const bool keyboard_message = message >= WM_KEYFIRST && message <= WM_KEYLAST;
        const bool mouse_message = message >= WM_MOUSEFIRST && message <= WM_MOUSELAST;
        if (visible && (imgui_result != 0 || (keyboard_message && io.WantCaptureKeyboard) ||
                        (mouse_message && io.WantCaptureMouse))) {
            return 0;
        }
    }
    return CallWindowProcW(original_wnd_proc, window, message, w_param, l_param);
}

void initialize_imgui(IDXGISwapChain* swap_chain) {
    // Creates the ImGui context and render target from the first valid game swap chain.
    DXGI_SWAP_CHAIN_DESC description{};
    if (swap_chain == nullptr || FAILED(swap_chain->GetDesc(&description))) {
        launcher::diagnostics::show_error(L"Client", L"The Direct3D 11 swap-chain description is unavailable.",
                                          L"Update the client for the active GTA V renderer configuration.");
        return;
    }
    launcher::diagnostics::log(L"INFO", L"Overlay", L"Initializing ImGui from the first valid DXGI swap chain.");
    game_window = description.OutputWindow;
    HMODULE client_module = nullptr;
    wchar_t module_path[MAX_PATH]{};
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(&initialize_imgui), &client_module) != 0 &&
        GetModuleFileNameW(client_module, module_path, MAX_PATH) != 0) {
        gui_settings = launcher::config::load(std::filesystem::path(module_path).parent_path()).gui;
    } else {
        launcher::diagnostics::log(L"WARNING", L"Overlay",
                                   L"Client module path is unavailable; GUI defaults are used.");
    }
    const UINT dpi = GetDpiForWindow(game_window);
    const float dpi_scale = static_cast<float>(dpi) / 96.0F;
    const float resolution_scale = static_cast<float>(description.BufferDesc.Width) / 1920.0F;
    ui_scale = gui_settings.scale > 0.0F ? gui_settings.scale : (std::max)({1.0F, dpi_scale, resolution_scale});
    ui_scale = (std::min)(ui_scale, 3.0F);
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
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.FontGlobalScale = ui_scale;
    ImGui::GetStyle().ScaleAllSizes(ui_scale);
    if (!ImGui_ImplWin32_Init(game_window) || !ImGui_ImplDX11_Init(device, context)) {
        launcher::diagnostics::show_error(
            L"Client", L"ImGui could not initialize its Win32 or Direct3D 11 backend.",
            L"Keep the ImGui runtime compatible with the built Client.dll and use Direct3D 11.");
        return;
    }
    initialized = render_target != nullptr;
    if (initialized) {
        SetLastError(ERROR_SUCCESS);
        original_wnd_proc = reinterpret_cast<WNDPROC>(
            SetWindowLongPtrW(game_window, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&overlay_wnd_proc)));
        if (original_wnd_proc == nullptr && GetLastError() != ERROR_SUCCESS) {
            launcher::diagnostics::show_error(
                L"Client", L"The game window procedure could not be hooked for ImGui input.",
                L"Run the game with a standard Win32 window and disable window-hooking software.", GetLastError());
            ImGui_ImplDX11_Shutdown();
            ImGui_ImplWin32_Shutdown();
            ImGui::DestroyContext();
            initialized = false;
            return;
        }
        launcher::diagnostics::log(L"INFO", L"Overlay",
                                   L"ImGui input enabled; UI scale is " + std::to_wstring(ui_scale) + L"x.");
    }
    launcher::diagnostics::log(initialized ? L"INFO" : L"ERROR", L"Overlay",
                               initialized ? L"Direct3D 11 overlay initialized." : L"Render target creation failed.");
}

HRESULT STDMETHODCALLTYPE present_hook(IDXGISwapChain* swap_chain, const UINT sync_interval, const UINT flags) {
    // Draws the diagnostic overlay once per frame before calling the original Present method.
    if (!initialized) {
        initialize_imgui(swap_chain);
    }
    const bool toggle_pressed = (GetAsyncKeyState(VK_F4) & 0x8000) != 0;
    if (toggle_pressed && !previous_toggle_state) {
        visible = !visible;
        launcher::diagnostics::log(L"INFO", L"Overlay",
                                   visible ? L"Overlay shown with F4." : L"Overlay hidden with F4.");
    }
    previous_toggle_state = toggle_pressed;

    if (initialized && visible) {
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        ImGui::SetNextWindowSize(ImVec2(gui_settings.window_width * ui_scale, gui_settings.window_height * ui_scale),
                                 ImGuiCond_FirstUseEver);
        ImGui::Begin("GTA Launcher", &visible, ImGuiWindowFlags_NoCollapse);
        ImGui::TextUnformatted("GTA V Python scripting");
        ImGui::Separator();
        ImGui::Text("Process: GTA5.exe (PID %lu)", GetCurrentProcessId());
        ImGui::Text("Game hooks installed: %zu", game::installed_count());
        ImGui::Text("Renderer: Direct3D 11");
        const auto available_scripts = python::scripts();
        std::vector<std::string> script_names;
        std::vector<const char*> names;
        script_names.reserve(available_scripts.size());
        names.reserve(available_scripts.size());
        for (const auto& script : available_scripts) {
            script_names.push_back(script.filename().string());
            names.push_back(script_names.back().c_str());
        }
        if (selected_script >= static_cast<int>(names.size())) {
            selected_script = 0;
        }
        if (!names.empty()) {
            ImGui::Combo("Script", &selected_script, names.data(), static_cast<int>(names.size()));
            if (ImGui::Button("Run script") && !python::running()) {
                static_cast<void>(python::run(available_scripts[static_cast<std::size_t>(selected_script)]));
            }
        } else {
            ImGui::TextUnformatted("No .py files found in scripts\\.");
        }
        ImGui::SameLine();
        if (ImGui::Button("Stop")) {
            python::stop();
        }
        ImGui::SameLine();
        if (ImGui::Button("Clear console")) {
            python::clear_console();
        }
        ImGui::Text("Status: %s", python::running() ? python::active_script().c_str() : "idle");
        ImGui::Separator();
        ImGui::BeginChild("Python console", ImVec2(0.0F, gui_settings.console_height * ui_scale), true);
        for (const auto& line : python::console_lines()) {
            ImGui::TextUnformatted(line.c_str());
        }
        ImGui::EndChild();
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
    launcher::diagnostics::log(L"INFO", L"Overlay", L"d3d11.dll is available; installing device creation hook.");
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
    launcher::diagnostics::log(L"INFO", L"Overlay", L"Direct3D 11 device creation hook installed.");
}

void remove() {
    // Releases the renderer resources and disables the overlay hook during controlled shutdown.
    if (!installed) {
        return;
    }
    MH_DisableHook(MH_ALL_HOOKS);
    if (initialized) {
        if (original_wnd_proc != nullptr) {
            SetWindowLongPtrW(game_window, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(original_wnd_proc));
            original_wnd_proc = nullptr;
        }
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
    launcher::diagnostics::log(L"INFO", L"Overlay", L"Direct3D 11 overlay removed.");
}

} // namespace client::overlay
