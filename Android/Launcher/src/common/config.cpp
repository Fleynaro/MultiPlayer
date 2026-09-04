#include "common/config.h"

#include "common/diagnostics.h"

#include <Windows.h>
#include <string>

namespace launcher::config {
namespace {

std::wstring read_value(const std::filesystem::path& file, const wchar_t* section, const wchar_t* key,
                        const wchar_t* default_value) {
    std::wstring value(32768, L'\0');
    const DWORD length = GetPrivateProfileStringW(section, key, default_value, value.data(),
                                                  static_cast<DWORD>(value.size()), file.c_str());
    value.resize(length);
    return value;
}

std::filesystem::path resolve_path(const std::filesystem::path& runtime_directory, const std::wstring& value) {
    const std::filesystem::path configured(value);
    return configured.is_absolute() ? configured : runtime_directory / configured;
}

} // namespace

Settings load(const std::filesystem::path& runtime_directory) {
    const auto config_file = runtime_directory / L"Launcher.ini";
    Settings settings{
        .runtime_directory = runtime_directory,
        .config_file = config_file,
        .game_install_directory = {},
        .scripts_directory =
            resolve_path(runtime_directory, read_value(config_file, L"Python", L"ScriptsDirectory", L"scripts")),
        .site_packages_directory =
            resolve_path(runtime_directory,
                         read_value(config_file, L"Python", L"SitePackagesDirectory", L".venv\\Lib\\site-packages")),
    };

    const std::wstring game_directory = read_value(config_file, L"Launcher", L"GameInstallDirectory", L"");
    if (!game_directory.empty()) {
        settings.game_install_directory = resolve_path(runtime_directory, game_directory);
    }

    if (!std::filesystem::is_regular_file(config_file)) {
        diagnostics::log(L"WARNING", L"Config", L"Launcher.ini was not found; built-in defaults are being used.");
    } else {
        diagnostics::log(L"INFO", L"Config", L"Launcher.ini loaded from the runtime directory.");
    }
    diagnostics::log(L"INFO", L"Config", L"Python scripts directory: " + settings.scripts_directory.wstring());
    return settings;
}

} // namespace launcher::config
