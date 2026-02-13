#pragma once
#include <cstdint>

struct trap_frame_t;

namespace core {

struct business_callbacks {
  void (*on_first_vmexit)(std::uint64_t ntoskrnl_base);
  bool (*on_vmexit)(std::uint64_t exit_reason, trap_frame_t *trap_frame);
};

void set_business_callbacks(const business_callbacks *callbacks);

void initialize(std::uint8_t **const vmexit_handler_detour_out,
                std::uint8_t *const original_vmexit_handler_routine,
                const std::uint64_t heap_physical_base,
                const std::uint64_t heap_physical_usable_base,
                const std::uint64_t heap_total_size,
                const std::uint64_t _uefi_boot_physical_base_address,
                const std::uint32_t _uefi_boot_image_size,
                const std::uint64_t reserved_one,
                const std::uint64_t ntoskrnl_base_from_uefi);

std::uint64_t dispatch_vmexit(const std::uint64_t a1, const std::uint64_t a2,
                              const std::uint64_t a3, const std::uint64_t a4);

} // namespace core
