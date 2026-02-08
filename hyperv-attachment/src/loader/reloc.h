#pragma once
// =============================================================================
// VMM Shadow Mapper - Relocation Engine
// Ported from kdmapper::RelocateImageByDelta
// =============================================================================

#include <cstdint>

namespace loader {

// Apply relocations to a payload image loaded at a different base address
// @param payload_image: Pointer to the loaded PE image in memory
// @param target_va: The virtual address where the payload will execute
// @return: true if relocations applied successfully, false on error
bool apply_relocations(void* payload_image, uint64_t target_va);

} // namespace loader
