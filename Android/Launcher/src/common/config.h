#pragma once

#include <filesystem>
#include <vector>

namespace launcher::config {

struct GuiSettings {
    // A non-positive value enables automatic DPI/resolution scaling.
    float scale = 0.0F;
    float window_width = 620.0F;
    float window_height = 420.0F;
    float console_height = 180.0F;
};

struct Settings {
    std::filesystem::path runtime_directory;
    std::filesystem::path config_file;
    std::filesystem::path game_install_directory;
    std::filesystem::path scripts_directory;
    std::filesystem::path site_packages_directory;
    std::vector<std::filesystem::path> auto_start_scripts;
    GuiSettings gui;
};

// Loads Launcher.ini beside the executable and resolves relative paths from that directory.
[[nodiscard]] Settings load(const std::filesystem::path& runtime_directory);

} // namespace launcher::config
