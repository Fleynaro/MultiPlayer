#pragma once

#include <string_view>

namespace launcher::crash_handler {

// Installs process-wide handlers for unhandled Windows and C++ exceptions.
void install(std::wstring_view component);

} // namespace launcher::crash_handler
