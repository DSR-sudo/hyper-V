// =============================================================================
// VMM Shadow Mapper - Security Cookie Fixer
// Ported from kdmapper::FixSecurityCookie by @Jerem584
// =============================================================================

#include "cookie.h"
#include "pe.h"
#include "../logs/logs.h"

namespace loader {

bool fix_security_cookie(void* payload_image, const uint64_t kernel_image_base)
{
    if (!payload_image) {
        logs::print("[Loader] fix_security_cookie: Invalid image pointer\n");
        return false;
    }

    // Get NT headers
    const auto nt_headers = get_nt_headers(payload_image);
    if (!nt_headers) {
        logs::print("[Loader] fix_security_cookie: Invalid PE headers\n");
        return false;
    }

    // Get load config directory
    const auto& load_config_dir = nt_headers->optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if (!load_config_dir.virtual_address) {
        // No load config directory - security cookie not defined
        logs::print("[Loader] fix_security_cookie: No LOAD_CONFIG directory, skipping\n");
        return true;
    }

    // Get load config structure
    const auto load_config = reinterpret_cast<image_load_config_directory64_t*>(
        reinterpret_cast<uint64_t>(payload_image) + load_config_dir.virtual_address
    );

    // Check if security cookie is defined
    if (!load_config->security_cookie) {
        // No security cookie defined
        logs::print("[Loader] fix_security_cookie: SecurityCookie not defined, skipping\n");
        return true;
    }

    // The security_cookie field contains the VA of the cookie in the original image
    // We need to translate this to our local copy
    // Since our image is already mapped at payload_image, we compute:
    // local_cookie_addr = cookie_va - kernel_image_base + local_image_base

    const uint64_t local_image_base = reinterpret_cast<uint64_t>(payload_image);
    
    // The cookie VA is stored relative to the kernel target base after relocation
    // But before relocation, it's relative to the original ImageBase
    // Since relocations are applied AFTER cookie fix in kdmapper, we use original base
    const uint64_t original_image_base = nt_headers->optional_header.image_base;
    
    // Calculate local address of the cookie
    uint64_t cookie_va = load_config->security_cookie;
    
    // If the image has been relocated already, cookie_va points to kernel space
    // Adjust based on whether it looks like kernel or local address
    uint64_t local_cookie_addr;
    
    if (cookie_va >= kernel_image_base && kernel_image_base != 0) {
        // Cookie VA is in kernel space (post-relocation scenario)
        local_cookie_addr = cookie_va - kernel_image_base + local_image_base;
    }
    else if (cookie_va >= original_image_base) {
        // Cookie VA is relative to original ImageBase (pre-relocation)
        local_cookie_addr = cookie_va - original_image_base + local_image_base;
    }
    else {
        // Cookie VA is an RVA or something unexpected
        local_cookie_addr = local_image_base + cookie_va;
    }

    // Read current cookie value
    uint64_t* const cookie_ptr = reinterpret_cast<uint64_t*>(local_cookie_addr);
    const uint64_t current_cookie = *cookie_ptr;

    // Check if cookie has default uninitialized value
    if (current_cookie != DEFAULT_SECURITY_COOKIE) {
        logs::print("[Loader] fix_security_cookie: Cookie already modified (0x%p), potential issue\n", 
            current_cookie);
        // Continue anyway - might be intentional
    }

    logs::print("[Loader] Fixing security cookie at local addr 0x%p (current: 0x%p)\n",
        local_cookie_addr, current_cookie);

    // Generate a new cookie value
    // In VMM we don't have GetCurrentProcessId/ThreadId, so we use a simple approach
    // Mix the kernel base address and image base for some entropy
    uint64_t new_cookie = DEFAULT_SECURITY_COOKIE;
    new_cookie ^= kernel_image_base;
    new_cookie ^= local_image_base;
    new_cookie ^= reinterpret_cast<uint64_t>(payload_image);
    
    // Ensure new cookie is different from default
    if (new_cookie == DEFAULT_SECURITY_COOKIE) {
        new_cookie = DEFAULT_SECURITY_COOKIE + 1;
    }

    // Write new cookie
    *cookie_ptr = new_cookie;

    logs::print("[Loader] Security cookie fixed: 0x%p -> 0x%p\n", current_cookie, new_cookie);

    return true;
}

} // namespace loader
