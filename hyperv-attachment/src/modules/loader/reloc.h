#pragma once
// =============================================================================
// VMM Shadow Mapper - Relocation Engine
// Ported from kdmapper::RelocateImageByDelta
// =============================================================================

#include <cstdint>

namespace loader {

struct context_t;

// Apply relocations to a payload image loaded at a different base address
// @param ctx: Loader context
// @param payload_image: Pointer to the loaded PE image in memory
// @param target_va: The virtual address where the payload will execute
// @return: true if relocations applied successfully, false on error
bool apply_relocations(context_t* ctx, void* payload_image, uint64_t target_va);

} // namespace loader
