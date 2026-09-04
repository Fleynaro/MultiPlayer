#include "client/game_hooks.h"

#include "client/pattern_scanner.h"
#include "client/python_runtime.h"
#include "common/diagnostics.h"

#include <MinHook.h>
#include <Windows.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace client::game {

namespace {

using ExecuteScript = int(__fastcall*)(void*);
using SpawnPeds = std::uintptr_t(__fastcall*)(std::uintptr_t, int, std::uintptr_t, int);
using SpawnVehicle = std::uintptr_t(__fastcall*)(std::uintptr_t, float*, std::uintptr_t, bool, bool, unsigned char);
using VoidFunction = void(__fastcall*)();
using SpecialSkillFunction = std::uintptr_t(__fastcall*)(int);
using RegisterNative = void(__fastcall*)(void*, std::uint64_t, void*);

struct NativeStack {
    std::uint64_t data[32]{};
};

struct NativeContext {
    NativeStack* returns;
    std::uint32_t argument_count;
    NativeStack* arguments;
    std::uint32_t data_count;
    std::uint64_t reserved[24]{};
};

ExecuteScript original_execute_script = nullptr;
SpawnPeds original_spawn_peds = nullptr;
SpawnVehicle original_spawn_vehicle = nullptr;
std::atomic_size_t installed_hooks = 0;
std::atomic_size_t missing_patterns = 0;
std::atomic_size_t failed_hooks = 0;
thread_local const char* executing_script = nullptr;
RegisterNative original_register_native = nullptr;
std::unordered_map<std::uint64_t, void*> native_handlers;
std::unordered_map<std::uint64_t, std::uint64_t> native_hash_mapping;

std::wstring hex_value(const std::uintptr_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}

std::wstring native_hash(const std::uint64_t hash) {
    return hex_value(static_cast<std::uintptr_t>(hash));
}

std::filesystem::path client_directory() {
    wchar_t module_path[MAX_PATH]{};
    HMODULE module = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCWSTR>(&install), &module);
    const DWORD length = GetModuleFileNameW(module, module_path, MAX_PATH);
    return length == 0 ? std::filesystem::current_path() : std::filesystem::path(module_path).parent_path();
}

void load_native_hash_mapping() {
    const auto mapping_file = client_directory() / L"hashes_ver141.json";
    std::ifstream input(mapping_file);
    if (!input.is_open()) {
        launcher::diagnostics::log(L"WARNING", L"GameHooks",
                                   L"Native hash mapping file could not be opened: " + mapping_file.wstring() +
                                       L". Native calls will use their original hashes.");
        return;
    }

    const std::string content((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    const std::regex pair_pattern(R"REGEX(\[\s*"0x([0-9A-Fa-f]+)"\s*,\s*"0x([0-9A-Fa-f]+)"\s*\])REGEX");
    std::size_t parsed_pairs = 0;
    for (std::sregex_iterator it(content.begin(), content.end(), pair_pattern), end; it != end; ++it) {
        try {
            const auto old_hash = std::stoull((*it)[1].str(), nullptr, 16);
            const auto new_hash = std::stoull((*it)[2].str(), nullptr, 16);
            native_hash_mapping[old_hash] = new_hash;
            ++parsed_pairs;
        } catch (const std::exception& error) {
            (void)error;
            launcher::diagnostics::log(L"WARNING", L"GameHooks",
                                       L"Invalid native hash mapping entry in hashes_ver141.json.");
        }
    }
    launcher::diagnostics::log(L"INFO", L"GameHooks",
                               L"Loaded native hash mapping: file='" + mapping_file.wstring() + L"', pairs=" +
                                   std::to_wstring(parsed_pairs) + L".");
}

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
    python::pump_game_thread();
    if (name != nullptr && !is_enabled_script(name)) {
        const std::wstring script(name, name + std::strlen(name));
        launcher::diagnostics::log(L"INFO", L"GameHooks", L"Suppressed disabled script: " + script);
        executing_script = nullptr;
        return 0;
    }
    const int result = original_execute_script(context);
    executing_script = nullptr;
    return result;
}

void __fastcall register_native_hook(void* table, const std::uint64_t hash, void* handler) {
    const auto existing = native_handlers.find(hash);
    const std::wstring previous_handler =
        existing == native_handlers.end() ? L"none" : hex_value(reinterpret_cast<std::uintptr_t>(existing->second));
    if (handler != nullptr) {
        native_handlers[hash] = handler;
    }
    launcher::diagnostics::log(
        L"INFO", L"GameHooks",
        L"RegisterNative called: table=" + hex_value(reinterpret_cast<std::uintptr_t>(table)) + L", hash=" +
            native_hash(hash) + L", handler=" + hex_value(reinterpret_cast<std::uintptr_t>(handler)) + L", previous=" +
            previous_handler + L", registered_handlers=" + std::to_wstring(native_handlers.size()) + L".");
    if (original_register_native != nullptr) {
        original_register_native(table, hash, handler);
    } else {
        launcher::diagnostics::log(
            L"ERROR", L"GameHooks",
            L"RegisterNative handler has no original function. The game registration call was not forwarded.");
    }
}

std::uintptr_t __fastcall spawn_peds_hook(const std::uintptr_t first, const int mode, const std::uintptr_t third,
                                          const int flags) {
    // Blocks the single-player ped spawn mode used by the documented implementation.
    if (mode == 4 && flags == 1) {
        // launcher::diagnostics::log(L"INFO", L"GameHooks", L"Suppressed single-player ped spawn request.");
        return 1;
    }
    return original_spawn_peds(first, mode, third, flags);
}

std::uintptr_t __fastcall spawn_vehicle_hook(const std::uintptr_t first, float* position, const std::uintptr_t third,
                                             const bool fourth, const bool fifth, const unsigned char flags) {
    // Blocks vehicle_gen_controller traffic while preserving other vehicle creation calls.
    if (executing_script != nullptr && _stricmp(executing_script, "vehicle_gen_controller") == 0) {
        // launcher::diagnostics::log(L"INFO", L"GameHooks", L"Suppressed vehicle_gen_controller vehicle spawn
        // request.");
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

bool install_hook(const std::wstring_view hook_name, const std::uintptr_t target, void* detour, void** original) {
    // Creates and enables one MinHook detour without modifying state on failure.
    if (target == 0) {
        ++missing_patterns;
        launcher::diagnostics::log(L"WARNING", L"GameHooks",
                                   L"Hook target was not found: name='" + std::wstring(hook_name) + L"', detour=" +
                                       hex_value(reinterpret_cast<std::uintptr_t>(detour)) + L".");
        return false;
    }
    launcher::diagnostics::log(L"INFO", L"GameHooks",
                               L"Creating hook: name='" + std::wstring(hook_name) + L"', target=" + hex_value(target) +
                                   L", detour=" + hex_value(reinterpret_cast<std::uintptr_t>(detour)) + L".");
    const MH_STATUS create_status = MH_CreateHook(reinterpret_cast<void*>(target), detour, original);
    const MH_STATUS enable_status =
        create_status == MH_OK ? MH_EnableHook(reinterpret_cast<void*>(target)) : create_status;
    if (enable_status != MH_OK) {
        ++failed_hooks;
        launcher::diagnostics::log(L"ERROR", L"GameHooks",
                                   L"MinHook failed for hook '" + std::wstring(hook_name) + L"'. Status: " +
                                       std::to_wstring(static_cast<int>(enable_status)) + L", target address: " +
                                       hex_value(target) + L", create status: " +
                                       std::to_wstring(static_cast<int>(create_status)) + L".");
        return false;
    }
    ++installed_hooks;
    launcher::diagnostics::log(
        L"INFO", L"GameHooks",
        L"Hook installed: '" + std::wstring(hook_name) + L"', target address: " + hex_value(target) + L", original=" +
            hex_value(original != nullptr && *original != nullptr ? reinterpret_cast<std::uintptr_t>(*original) : 0) +
            L".");
    return true;
}

void install_suppressed(const std::wstring_view hook_name, HMODULE module, const char* signature,
                        const std::ptrdiff_t adjustment = 0, const bool rip_target = false) {
    // Finds and suppresses one optional build-specific single-player procedure.
    auto target = memory::find_pattern(module, signature);
    if (target == 0) {
        ++missing_patterns;
        launcher::diagnostics::log(L"WARNING", L"GameHooks",
                                   L"Optional hook was not installed: '" + std::wstring(hook_name) + L"'; signature: " +
                                       std::wstring(signature, signature + std::strlen(signature)) + L"; adjustment: " +
                                       std::to_wstring(adjustment) + L"; RIP-relative: " +
                                       (rip_target ? L"yes" : L"no") + L".");
        return;
    }
    const auto raw_target = target;
    target += adjustment;
    if (rip_target) {
        target = memory::rip_relative(target, 1, 5);
    }
    launcher::diagnostics::log(L"INFO", L"GameHooks",
                               L"Resolved optional hook: name='" + std::wstring(hook_name) + L"', raw_match=" +
                                   hex_value(raw_target) + L", final_target=" + hex_value(target) + L", adjustment=" +
                                   std::to_wstring(adjustment) + L", RIP-relative=" + (rip_target ? L"yes" : L"no") +
                                   L".");
    install_hook(hook_name, target, reinterpret_cast<void*>(&suppress_void_hook), nullptr);
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
    launcher::diagnostics::log(L"INFO", L"GameHooks",
                               L"Starting game hook installation: module=" +
                                   hex_value(reinterpret_cast<std::uintptr_t>(game)) + L", existing_handlers=" +
                                   std::to_wstring(native_handlers.size()) + L".");
    load_native_hash_mapping();
    const MH_STATUS min_hook_status = MH_Initialize();
    if (min_hook_status != MH_OK && min_hook_status != MH_ERROR_ALREADY_INITIALIZED) {
        launcher::diagnostics::show_error(L"Client", L"MinHook could not be initialized.",
                                          L"Use the x64 client build and remove conflicting hook libraries.");
        return;
    }
    launcher::diagnostics::log(L"INFO", L"GameHooks", L"MinHook initialized for GTA V game hooks.");

    const auto script =
        memory::find_pattern(game, "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 80 B9 ?? ?? 00 00 00 8B FA 48 8B D9");
    install_hook(L"ExecuteScript", script, reinterpret_cast<void*>(&execute_script_hook),
                 reinterpret_cast<void**>(&original_execute_script));

    const auto register_native = memory::find_pattern(game, "48 BA 9C 13 0A F4 62 B1 FF D0 48 8B CB E8 ?? ?? ?? ??");
    if (register_native != 0) {
        // The legacy scanner used '*??' to return the address of the call's
        // displacement. This scanner returns the beginning of the signature,
        // so resolve the E8 call at byte 13 explicitly.
        constexpr std::size_t register_native_call_offset = 13;
        const auto register_native_call = register_native + register_native_call_offset;
        const auto register_native_target = memory::rip_relative(register_native_call, 1, 5);
        launcher::diagnostics::log(L"INFO", L"GameHooks",
                                   L"RegisterNative signature matched at " + hex_value(register_native) + L"; call=" +
                                       hex_value(register_native_call) + L"; resolved target=" +
                                       hex_value(register_native_target) + L".");
        install_hook(L"RegisterNative", register_native_target, reinterpret_cast<void*>(&register_native_hook),
                     reinterpret_cast<void**>(&original_register_native));
    } else {
        ++missing_patterns;
        launcher::diagnostics::log(L"WARNING", L"GameHooks",
                                   L"Native registration signature was not found; no native handlers can be captured.");
    }

    const auto peds = memory::find_pattern(game, "85 D2 0F 88 BA 00 00 00 B8 01 00 00 00 75");
    install_hook(L"SpawnPeds", peds, reinterpret_cast<void*>(&spawn_peds_hook),
                 reinterpret_cast<void**>(&original_spawn_peds));

    const auto vehicles = memory::find_pattern(game, "8D 64 24 08 8B 0A 48 83 C2 08 E9 ?? ?? ?? ?? E8");
    install_hook(L"SpawnVehicle", vehicles, reinterpret_cast<void*>(&spawn_vehicle_hook),
                 reinterpret_cast<void**>(&original_spawn_vehicle));

    install_suppressed(L"SuppressPedStartup", game, "FF FF E8 ?? ?? ?? ?? 45 33 FF 41 BC 01 00 00 00 84", -94);
    install_suppressed(L"SuppressFireDispatch", game, "00 E8 ?? ?? ?? ?? 80 3D ?? ?? ?? ?? 00 74 3D 80 3D", 0, true);
    install_suppressed(L"SuppressDistantFakeVehicles", game, "00 E8 ?? ?? ?? ?? 80 3D ?? ?? ?? ?? 00 74 3D 80 3D", 1,
                       true);
    install_suppressed(L"SuppressVehicleStartup", game, "48 83 EC 50 41 8B 80 ?? 00 00 00 41 BF 04 00 00 00 4D 8B",
                       -19);
    install_suppressed(L"SuppressWantedUpdate", game, "E8 ?? ?? ?? ?? 80 3D ?? ?? ?? ?? 00 74 3D 80 3D", 0, true);
    install_suppressed(L"SuppressPoliceUpdate", game, "48 8B CF E8 ?? ?? ?? ?? 33 DB 45 84 E4 74 4D", 3, true);
    install_suppressed(L"SuppressStartupSpawning", game, "8B D7 89 5C 24 28 C6 44 24 20 01 E8 ?? ?? ?? ??", 12, true);
    install_suppressed(L"SuppressSpecialVehicleBehavior", game, "0F 29 45 E7 44 88 7C 24 20 E8 ?? ?? ?? ?? BA 00", 10,
                       true);

    // const auto special_skill = memory::find_pattern(game, "83 F8 FF 74 0E 8B C8 E8 ?? ?? ?? ?? 48 89 83");
    // install_hook(L"SuppressSpecialSkill", special_skill, reinterpret_cast<void*>(&suppress_special_skill), nullptr);
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
    launcher::diagnostics::log(
        L"INFO", L"GameHooks",
        L"Game hook installation finished. Installed: " + std::to_wstring(installed_hooks.load()) + L", missing: " +
            std::to_wstring(missing_patterns.load()) + L", failed: " + std::to_wstring(failed_hooks.load()) +
            L", registered native handlers: " + std::to_wstring(native_handlers.size()) + L".");
}

void remove() {
    // Disables all MinHook detours before the client DLL is unloaded.
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    installed_hooks = 0;
    missing_patterns = 0;
    failed_hooks = 0;
    launcher::diagnostics::log(L"INFO", L"GameHooks", L"Game hooks removed and MinHook uninitialized.");
}

std::size_t installed_count() {
    // Returns the number of successfully enabled game detours for the overlay.
    return installed_hooks.load();
}
const char* current_script() {
    // Returns the script currently being executed on this game thread, if known.
    return executing_script;
}

std::vector<std::uint64_t> invoke_native(const std::uint64_t hash, const std::vector<std::uint64_t>& arguments,
                                         const std::size_t result_count) {
    const auto mapping = native_hash_mapping.find(hash);
    const std::uint64_t runtime_hash = mapping == native_hash_mapping.end() ? hash : mapping->second;
    launcher::diagnostics::log(L"INFO", L"GameHooks",
                               L"Native invoke requested: static_hash=" + native_hash(hash) + L", runtime_hash=" +
                                   native_hash(runtime_hash) + L", mapped=" +
                                   (mapping == native_hash_mapping.end() ? L"no" : L"yes") + L", arguments=" +
                                   std::to_wstring(arguments.size()) + L", results=" + std::to_wstring(result_count) +
                                   L", registered_handlers=" + std::to_wstring(native_handlers.size()) + L".");
    if (arguments.size() > 32 || result_count > 3) {
        launcher::diagnostics::log(L"ERROR", L"GameHooks",
                                   L"Native invoke rejected by ABI limits: hash=" + native_hash(hash) + L".");
        throw std::invalid_argument("native argument or result count exceeds the GTA script ABI limit");
    }
    const auto handler = native_handlers.find(runtime_hash);
    if (handler == native_handlers.end() || handler->second == nullptr) {
        launcher::diagnostics::log(L"ERROR", L"GameHooks",
                                   L"Native handler not found: static_hash=" + native_hash(hash) + L", runtime_hash=" +
                                       native_hash(runtime_hash) + L", registered_handlers=" +
                                       std::to_wstring(native_handlers.size()) + L", register_hook_original=" +
                                       hex_value(reinterpret_cast<std::uintptr_t>(original_register_native)) + L".");
        throw std::runtime_error("native handler is not registered for the current GTA build; hash=" +
                                 std::to_string(hash));
    }
    launcher::diagnostics::log(L"INFO", L"GameHooks",
                               L"Native handler found: hash=" + native_hash(hash) + L", handler=" +
                                   hex_value(reinterpret_cast<std::uintptr_t>(handler->second)) + L".");
    NativeStack returns{};
    NativeStack args{};
    std::copy(arguments.begin(), arguments.end(), std::begin(args.data));
    NativeContext context{&returns, static_cast<std::uint32_t>(arguments.size()), &args, 0, {}};
    using Handler = void(__fastcall*)(NativeContext*);
    reinterpret_cast<Handler>(handler->second)(&context);
    return std::vector<std::uint64_t>(returns.data, returns.data + result_count);
}

} // namespace client::game
