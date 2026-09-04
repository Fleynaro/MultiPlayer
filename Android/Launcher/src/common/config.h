#pragma once

#include <filesystem>

namespace launcher::config {

struct Settings {
    std::filesystem::path runtime_directory;
    std::filesystem::path config_file;
    std::filesystem::path game_install_directory;
    std::filesystem::path scripts_directory;
    std::filesystem::path site_packages_directory;
};

// Loads Launcher.ini beside the executable and resolves relative paths from that directory.
[[nodiscard]] Settings load(const std::filesystem::path& runtime_directory);

} // namespace launcher::config
