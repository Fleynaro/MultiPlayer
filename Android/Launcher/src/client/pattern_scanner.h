#pragma once

#include <Windows.h>
#include <cstdint>
#include <string_view>

namespace client::memory {

// Finds the first matching byte signature in executable sections of a PE module.
[[nodiscard]] std::uintptr_t find_pattern(HMODULE module, std::string_view signature);

// Resolves a signed RIP-relative instruction operand into an absolute address.
[[nodiscard]] std::uintptr_t rip_relative(std::uintptr_t instruction, std::size_t displacement_offset,
                                          std::size_t instruction_size);

// Verifies that a memory range is committed and readable before dereferencing it.
[[nodiscard]] bool is_readable(const void* address, std::size_t size = 1);

} // namespace client::memory
