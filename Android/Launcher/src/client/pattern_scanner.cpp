#include "client/pattern_scanner.h"

#include "common/diagnostics.h"

#include <Psapi.h>
#include <charconv>
#include <string>
#include <vector>

namespace client::memory {

namespace {

std::vector<int> parse_signature(const std::string_view signature) {
    // Converts a textual byte signature into exact bytes and wildcard markers.
    std::vector<int> bytes;
    std::size_t position = 0;
    while (position < signature.size()) {
        while (position < signature.size() && signature[position] == ' ') {
            ++position;
        }
        if (position >= signature.size()) {
            break;
        }
        if (signature[position] == '?') {
            bytes.push_back(-1);
            position += position + 1 < signature.size() && signature[position + 1] == '?' ? 2 : 1;
            continue;
        }
        unsigned value = 0;
        const auto result = std::from_chars(signature.data() + position, signature.data() + position + 2, value, 16);
        if (result.ec != std::errc{}) {
            return {};
        }
        bytes.push_back(static_cast<int>(value));
        position += 2;
    }
    return bytes;
}

} // namespace

std::uintptr_t find_pattern(const HMODULE module, const std::string_view signature) {
    // Searches executable PE sections without reading non-code or unmapped memory.
    if (module == nullptr) {
        launcher::diagnostics::log(L"WARNING", L"PatternScanner", L"Pattern scan skipped because the module is null.");
        return 0;
    }
    const auto* base = reinterpret_cast<const std::byte*>(module);
    const auto* headers =
        reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + reinterpret_cast<const IMAGE_DOS_HEADER*>(base)->e_lfanew);
    const auto* section = IMAGE_FIRST_SECTION(headers);
    const auto pattern = parse_signature(signature);
    if (pattern.empty()) {
        launcher::diagnostics::log(L"ERROR", L"PatternScanner", L"Pattern parsing produced an empty signature.");
        return 0;
    }
    for (WORD index = 0; index < headers->FileHeader.NumberOfSections; ++index) {
        if ((section[index].Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
            continue;
        }
        const auto* start = base + section[index].VirtualAddress;
        const auto size = section[index].Misc.VirtualSize;
        for (std::size_t offset = 0; offset + pattern.size() <= size && !pattern.empty(); ++offset) {
            bool matches = true;
            for (std::size_t byte = 0; byte < pattern.size(); ++byte) {
                if (pattern[byte] >= 0 && static_cast<unsigned char>(start[offset + byte]) != pattern[byte]) {
                    matches = false;
                    break;
                }
            }
            if (matches) {
                const auto address = reinterpret_cast<std::uintptr_t>(start + offset);
                launcher::diagnostics::log(L"INFO", L"PatternScanner",
                                           L"Executable signature matched at address " + std::to_wstring(address) +
                                               L": " + std::wstring(signature.begin(), signature.end()));
                return address;
            }
        }
    }
    launcher::diagnostics::log(L"WARNING", L"PatternScanner",
                               L"Executable signature was not found: " +
                                   std::wstring(signature.begin(), signature.end()));
    return 0;
}

std::uintptr_t rip_relative(const std::uintptr_t instruction, const std::size_t displacement_offset,
                            const std::size_t instruction_size) {
    // Resolves a signed RIP-relative displacement into an absolute address.
    const auto displacement = *reinterpret_cast<const std::int32_t*>(instruction + displacement_offset);
    return instruction + instruction_size + displacement;
}

bool is_readable(const void* address, const std::size_t size) {
    // Checks that a memory range is committed and not protected by a guard page.
    if (address == nullptr || size == 0) {
        return false;
    }
    MEMORY_BASIC_INFORMATION info{};
    if (VirtualQuery(address, &info, sizeof(info)) != sizeof(info) || info.State != MEM_COMMIT ||
        (info.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) {
        return false;
    }
    const auto end = reinterpret_cast<std::uintptr_t>(address) + size;
    const auto region_end = reinterpret_cast<std::uintptr_t>(info.BaseAddress) + info.RegionSize;
    return end <= region_end;
}

} // namespace client::memory
