#pragma once

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace client::python {

void initialize();
void shutdown();
void pump_game_thread();

[[nodiscard]] std::vector<std::filesystem::path> scripts();
[[nodiscard]] bool run(const std::filesystem::path& script);
void stop();
[[nodiscard]] bool running();
[[nodiscard]] unsigned int active_script_count();
[[nodiscard]] std::string active_script();
[[nodiscard]] std::vector<std::string> console_lines();
void clear_console();

} // namespace client::python
