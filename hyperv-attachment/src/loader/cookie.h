#pragma once
// =============================================================================
// VMM Shadow Mapper - Security Cookie Fixer
// Ported from kdmapper::FixSecurityCookie
// =============================================================================

#include <cstdint>

namespace loader {

// Fix the security cookie in a payload image
// This is required because the stack cookie value is baked into the binary
// and needs patching when the image is relocated
// @param payload_image: Pointer to the loaded PE image in local memory
// @param kernel_image_base: Base address where payload will be mapped in kernel
// @return: true if cookie fixed or not needed, false on error
bool fix_security_cookie(void* payload_image, uint64_t kernel_image_base);

} // namespace loader
