#include "business/business.h"
#include "core/core.h"
#include <cstdint>

// The entry point called by the bootloader/driver loader.
// This function delegates all initialization to the core module.
extern "C" void
entry_point(std::uint8_t **const vmexit_handler_detour_out,
            std::uint8_t *const original_vmexit_handler_routine,
            const std::uint64_t heap_physical_base,
            const std::uint64_t heap_physical_usable_base,
            const std::uint64_t heap_total_size,
            const std::uint64_t _uefi_boot_physical_base_address,
            const std::uint32_t _uefi_boot_image_size,
            const std::uint64_t reserved_one,
            const std::uint64_t ntoskrnl_base_from_uefi) {

  // Delegate to core initialization
  // Core will set *vmexit_handler_detour_out to its internal dispatch handler
  core::set_business_callbacks(business::callbacks());
  core::initialize(vmexit_handler_detour_out, original_vmexit_handler_routine,
                   heap_physical_base, heap_physical_usable_base,
                   heap_total_size, _uefi_boot_physical_base_address,
                   _uefi_boot_image_size, reserved_one,
                   ntoskrnl_base_from_uefi);
}
