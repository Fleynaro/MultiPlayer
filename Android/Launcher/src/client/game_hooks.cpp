#include "client/game_hooks.h"

#include "client/pattern_scanner.h"
#include "common/diagnostics.h"

#include <MinHook.h>
#include <Windows.h>
#include <array>
#include <atomic>
#include <cstring>
#include <string>

namespace client::game {

namespace {

using ExecuteScript = int(__fastcall*)(void*);
using SpawnPeds = std::uintptr_t(__fastcall*)(std::uintptr_t, int, std::uintptr_t, int);
using SpawnVehicle = std::uintptr_t(__fastcall*)(std::uintptr_t, float*, std::uintptr_t, bool, bool, unsigned char);
using VoidFunction = void(__fastcall*)();
using SpecialSkillFunction = std::uintptr_t(__fastcall*)(int);

ExecuteScript original_execute_script = nullptr;
SpawnPeds original_spawn_peds = nullptr;
SpawnVehicle original_spawn_vehicle = nullptr;
std::atomic_size_t installed_hooks = 0;
std::atomic_size_t missing_patterns = 0;
std::atomic_size_t failed_hooks = 0;
thread_local const char* executing_script = nullptr;

constexpr std::array<const char*, 10> enabled_scripts = {"building_controller",
                                                         "initial",
                                                         "main",
                                                         "standard_global_init",
                                                         "pausemenu_map",
                                                         "standard_global_reg",
                                                         "startup",
                                                         "startup_positioning",
                                                         "vehicle_gen_controller",
                                                         "main_persistent"};

const char* script_name(void* context) {
    // Reads the script name from the documented GTA V build 1.41 context layout.
    if (!memory::is_readable(context, 0xD8)) {
        return nullptr;
    }
    const auto name = *reinterpret_cast<const char* const*>(static_cast<std::byte*>(context) + 0xD0);
    return memory::is_readable(name, 1) ? name : nullptr;
}

bool is_enabled_script(const char* name) {
    // Keeps only the core scripts required for the multiplayer-style world.
    if (name == nullptr) {
        return false;
    }
    for (const char* enabled : enabled_scripts) {
        if (_stricmp(name, enabled) == 0) {
            return true;
        }
    }
    return false;
}

int __fastcall execute_script_hook(void* context) {
    // Suppresses disabled single-player scripts while preserving allowed scripts.
    const char* name = script_name(context);
    executing_script = name;
    if (name != nullptr && !is_enabled_script(name)) {
        executing_script = nullptr;
        return 0;
    }
    const int result = original_execute_script(context);
    executing_script = nullptr;
    return result;
}

std::uintptr_t __fastcall spawn_peds_hook(const std::uintptr_t first, const int mode, const std::uintptr_t third,
                                          const int flags) {
    // Blocks the single-player ped spawn mode used by the documented implementation.
    if (mode == 4 && flags == 1) {
        return 1;
    }
    return original_spawn_peds(first, mode, third, flags);
}

std::uintptr_t __fastcall spawn_vehicle_hook(const std::uintptr_t first, float* position, const std::uintptr_t third,
                                             const bool fourth, const bool fifth, const unsigned char flags) {
    // Blocks vehicle_gen_controller traffic while preserving other vehicle creation calls.
    if (executing_script != nullptr && _stricmp(executing_script, "vehicle_gen_controller") == 0) {
        return 0;
    }
    return original_spawn_vehicle(first, position, third, fourth, fifth, flags);
}

// Replaces a single-player procedure whose side effects are not required by the client.
void __fastcall suppress_void_hook() {}

// Replaces the special-skill procedure with its documented disabled result.
std::uintptr_t __fastcall suppress_special_skill(int) {
    return 0;
}

bool install_hook(const std::uintptr_t target, void* detour, void** original) {
    // Creates and enables one MinHook detour without modifying state on failure.
    if (target == 0) {
        ++missing_patterns;
        return false;
    }
    if (MH_CreateHook(reinterpret_cast<void*>(target), detour, original) != MH_OK ||
        MH_EnableHook(reinterpret_cast<void*>(target)) != MH_OK) {
        ++failed_hooks;
        return false;
    }
    ++installed_hooks;
    return true;
}

void install_suppressed(HMODULE module, const char* signature, const std::ptrdiff_t adjustment = 0,
                        const bool rip_target = false) {
    // Finds and suppresses one optional build-specific single-player procedure.
    auto target = memory::find_pattern(module, signature);
    if (target == 0) {
        ++missing_patterns;
        return;
    }
    target += adjustment;
    if (rip_target) {
        target = memory::rip_relative(target, 1, 5);
    }
    install_hook(target, reinterpret_cast<void*>(&suppress_void_hook), nullptr);
}

} // namespace

void install() {
    // Initializes MinHook and installs all supported GTA V build 1.41 game hooks.
    const HMODULE game = GetModuleHandleW(nullptr);
    if (game == nullptr) {
        launcher::diagnostics::show_error(L"Client", L"The GTA5.exe module handle is unavailable.",
                                          L"Start the client through Bootstrap.dll inside GTA5.exe.");
        return;
    }
    if (MH_Initialize() != MH_OK) {
        launcher::diagnostics::show_error(L"Client", L"MinHook could not be initialized.",
                                          L"Use the x64 client build and remove conflicting hook libraries.");
        return;
    }

    const auto script =
        memory::find_pattern(game, "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 80 B9 ?? ?? 00 00 00 8B FA 48 8B D9");
    install_hook(script, reinterpret_cast<void*>(&execute_script_hook),
                 reinterpret_cast<void**>(&original_execute_script));

    const auto peds = memory::find_pattern(game, "85 D2 0F 88 BA 00 00 00 B8 01 00 00 00 75");
    install_hook(peds, reinterpret_cast<void*>(&spawn_peds_hook), reinterpret_cast<void**>(&original_spawn_peds));

    const auto vehicles = memory::find_pattern(game, "8D 64 24 08 8B 0A 48 83 C2 08 E9 ?? ?? ?? ?? E8");
    install_hook(vehicles, reinterpret_cast<void*>(&spawn_vehicle_hook),
                 reinterpret_cast<void**>(&original_spawn_vehicle));

    install_suppressed(game, "FF FF E8 ?? ?? ?? ?? 45 33 FF 41 BC 01 00 00 00 84", -94);
    install_suppressed(game, "00 E8 ?? ?? ?? ?? 80 3D ?? ?? ?? ?? 00 74 3D 80 3D", 0, true);
    install_suppressed(game, "00 E8 ?? ?? ?? ?? 80 3D ?? ?? ?? ?? 00 74 3D 80 3D", 1, true);
    install_suppressed(game, "48 83 EC 50 41 8B 80 ?? 00 00 00 41 BF 04 00 00 00 4D 8B", -19);
    install_suppressed(game, "E8 ?? ?? ?? ?? 80 3D ?? ?? ?? ?? 00 74 3D 80 3D", 0, true);
    install_suppressed(game, "48 8B CF E8 ?? ?? ?? ?? 33 DB 45 84 E4 74 4D", 3, true);
    install_suppressed(game, "8B D7 89 5C 24 28 C6 44 24 20 01 E8 ?? ?? ?? ??", 12, true);
    install_suppressed(game, "0F 29 45 E7 44 88 7C 24 20 E8 ?? ?? ?? ?? BA 00", 10, true);

    const auto special_skill = memory::find_pattern(game, "83 F8 FF 74 0E 8B C8 E8 ?? ?? ?? ?? 48 89 83");
    install_hook(special_skill, reinterpret_cast<void*>(&suppress_special_skill), nullptr);
    if (installed_hooks == 0) {
        launcher::diagnostics::show_error(L"Client", L"No GTA V game signatures were found.",
                                          L"Verify that the game is the supported 1.41 x64 build and update the "
                                          L"signatures before using this client.");
    } else if (missing_patterns != 0 || failed_hooks != 0) {
        const std::wstring details = L"Missing signatures: " + std::to_wstring(missing_patterns.load()) +
                                     L". Hook installation failures: " + std::to_wstring(failed_hooks.load()) + L".";
        launcher::diagnostics::show_warning(
            L"Client", L"Only a partial GTA V hook set is active. " + details,
            L"Use the supported 1.41 x64 build and review the changed signatures before reporting missing features.");
    }
}

void remove() {
    // Disables all MinHook detours before the client DLL is unloaded.
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    installed_hooks = 0;
    missing_patterns = 0;
    failed_hooks = 0;
}

std::size_t installed_count() {
    // Returns the number of successfully enabled game detours for the overlay.
    return installed_hooks.load();
}
const char* current_script() {
    // Returns the script currently being executed on this game thread, if known.
    return executing_script;
}

} // namespace client::game
