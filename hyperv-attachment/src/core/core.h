#pragma once
#include <cstdint>

namespace core {

// Initialization logic called by the main entry point
void initialize(std::uint8_t **const vmexit_handler_detour_out,
                std::uint8_t *const original_vmexit_handler_routine,
                const std::uint64_t heap_physical_base,
                const std::uint64_t heap_physical_usable_base,
                const std::uint64_t heap_total_size,
                const std::uint64_t _uefi_boot_physical_base_address,
                const std::uint32_t _uefi_boot_image_size,
                const std::uint64_t reserved_one,
                const std::uint64_t ntoskrnl_base_from_uefi);

// The VMExit handler that replaces the original one
std::uint64_t dispatch_vmexit(const std::uint64_t a1, const std::uint64_t a2,
                              const std::uint64_t a3, const std::uint64_t a4);

} // namespace core
