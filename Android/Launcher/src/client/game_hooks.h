#pragma once

#include <cstddef>

namespace client::game {

// Installs the build 1.41 game hooks and reports fatal problems to the user.
void install();

// Removes all game hooks during controlled client shutdown.
void remove();

// Returns the number of successfully enabled game hooks.
[[nodiscard]] std::size_t installed_count();

// Returns the name of the script currently executing on the game thread.
[[nodiscard]] const char* current_script();

} // namespace client::game
