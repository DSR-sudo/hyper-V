// =============================================================================
// VMM Shadow Mapper - Security Cookie Fixer
// Ported from kdmapper::FixSecurityCookie by @Jerem584
// =============================================================================

#include "cookie.h"
#include "pe.h"
#include "../logs/logs.h"

#include "guest.h"

namespace loader {

/**
 * @description 修复 Payload 的安全 Cookie 值。
 * @param {context_t*} ctx 加载器上下文。
 * @param {void*} payload_image Payload 镜像基址。
 * @param {uint64_t} kernel_image_base 内核目标基址。
 * @return {bool} 是否修复成功。
 * @throws {无} 不抛出异常。
 * @example
 * const auto ok = loader::fix_security_cookie(ctx, image_base, kernel_base);
 */
bool fix_security_cookie(context_t* ctx, void* payload_image, uint64_t kernel_image_base)
{
    if (!payload_image || !ctx) {
        logs::print(ctx ? ctx->log_ctx : nullptr, "[Loader] fix_security_cookie: Invalid arguments\n");
        return false;
    }

    const auto nt_headers = get_nt_headers(payload_image);
    if (!nt_headers) {
        logs::print(ctx->log_ctx, "[Loader] fix_security_cookie: Invalid PE headers\n");
        return false;
    }

    const auto& load_config_dir = nt_headers->optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if (!load_config_dir.virtual_address) {
        // No load config directory - security cookie not defined
        logs::print(ctx->log_ctx, "[Loader] fix_security_cookie: No LOAD_CONFIG directory, skipping\n");
        return true;
    }

    const auto load_config = reinterpret_cast<image_load_config_directory64_t*>(
        reinterpret_cast<uint64_t>(payload_image) + load_config_dir.virtual_address
    );

    if (!load_config->security_cookie) {
        // No security cookie defined
        logs::print(ctx->log_ctx, "[Loader] fix_security_cookie: SecurityCookie not defined, skipping\n");
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

    uint64_t* const cookie_ptr = reinterpret_cast<uint64_t*>(local_cookie_addr);
    const uint64_t current_cookie = *cookie_ptr;

    if (current_cookie != DEFAULT_SECURITY_COOKIE) {
        logs::print(ctx->log_ctx, "[Loader] fix_security_cookie: Cookie already modified (0x%p), potential issue\n",
            current_cookie);
        // Continue anyway - might be intentional
    }

    logs::print(ctx->log_ctx, "[Loader] Fixing security cookie at local addr 0x%p (current: 0x%p)\n",
        local_cookie_addr, current_cookie);

    // In VMM we don't have GetCurrentProcessId/ThreadId, so we use a simple approach
    // Mix the kernel base address and image base for some entropy
    uint64_t cookie_value = DEFAULT_SECURITY_COOKIE;
    cookie_value = cookie_value ^ kernel_image_base;
    cookie_value = cookie_value ^ local_image_base;
    cookie_value = cookie_value ^ reinterpret_cast<uint64_t>(payload_image);

    // Ensure new cookie is different from default
    if (cookie_value == DEFAULT_SECURITY_COOKIE) {
        cookie_value = DEFAULT_SECURITY_COOKIE + 1;
    }

    *cookie_ptr = cookie_value;

    logs::print(ctx->log_ctx, "[Loader] Security cookie fixed: 0x%p -> 0x%p\n", current_cookie, cookie_value);

    return true;
}

} // namespace loader
