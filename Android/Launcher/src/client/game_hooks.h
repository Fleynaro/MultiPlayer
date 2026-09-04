#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace client::game {

// Installs the build 1.41 game hooks and reports fatal problems to the user.
void install();

// Removes all game hooks during controlled client shutdown.
void remove();

// Returns the number of successfully enabled game hooks.
[[nodiscard]] std::size_t installed_count();

// Returns the name of the script currently executing on the game thread.
[[nodiscard]] const char* current_script();

// Executes a registered GTA native on the game thread using the script context ABI.
[[nodiscard]] std::vector<std::uint64_t> invoke_native(std::uint64_t hash,
                                                       const std::vector<std::uint64_t>& arguments,
                                                       std::size_t result_count);

} // namespace client::game
