#pragma once

namespace client::overlay {

// Installs the Direct3D 11 Present hook and initializes ImGui on first use.
void install();

// Removes the renderer hook and releases ImGui/Direct3D resources.
void remove();

} // namespace client::overlay
