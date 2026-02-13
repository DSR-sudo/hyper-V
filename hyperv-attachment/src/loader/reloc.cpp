// =============================================================================
// VMM Shadow Mapper - Relocation Engine
// Ported from kdmapper::RelocateImageByDelta
// =============================================================================

#include "reloc.h"
#include "pe.h"
#include "../logs/logs.h"
#include "../crt/crt.h"

namespace loader {

/**
 * @description 对 PE 镜像应用重定位修正。
 * @param {void*} payload_image 镜像基址。
 * @param {const uint64_t} target_va 目标加载地址。
 * @return {bool} 是否应用成功。
 * @throws {无} 不抛出异常。
 * @example
 * const auto ok = loader::apply_relocations(image_base, target_va);
 */
bool apply_relocations(void* payload_image, const uint64_t target_va)
{
    // 业务说明：解析重定位表并按目标地址差值修正 DIR64 项。
    // 输入：payload_image/target_va；输出：重定位修正结果；规则：无重定位表可直接成功；异常：不抛出。
    // Get NT headers
    const auto nt_headers = get_nt_headers(payload_image);
    if (!nt_headers) {
        logs::print("[Loader] apply_relocations: Invalid PE headers\n");
        return false;
    }

    // 业务说明：获取重定位目录并判断是否存在。
    // 输入：nt_headers；输出：reloc_dir；规则：不存在则直接成功；异常：不抛出。
    const auto& reloc_dir = nt_headers->optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!reloc_dir.virtual_address || !reloc_dir.size) {
        // No relocations needed - this is valid for PIC code like DKOM
        logs::print("[Loader] apply_relocations: No relocation table (PIC code?)\n");
        return true;
    }

    // 业务说明：计算目标加载地址与原始基址的差值。
    // 输入：target_va/original_image_base；输出：delta；规则：差值为 0 则无需重定位；异常：不抛出。
    const uint64_t original_image_base = nt_headers->optional_header.image_base;
    const int64_t delta = static_cast<int64_t>(target_va) - static_cast<int64_t>(original_image_base);

    if (delta == 0) {
        logs::print("[Loader] apply_relocations: Delta is 0, no relocation needed\n");
        return true;
    }

    logs::print("[Loader] Applying relocations: Original=0x%p, Target=0x%p, Delta=0x%p\n",
        original_image_base, target_va, delta);

    // 业务说明：定位重定位块并设置遍历边界。
    // 输入：payload_image/reloc_dir；输出：current_reloc/reloc_end；规则：按目录大小限定；异常：不抛出。
    auto current_reloc = reinterpret_cast<image_base_relocation_t*>(
        reinterpret_cast<uint64_t>(payload_image) + reloc_dir.virtual_address
    );

    const auto reloc_end = reinterpret_cast<image_base_relocation_t*>(
        reinterpret_cast<uint64_t>(current_reloc) + reloc_dir.size
    );

    uint32_t total_relocs_applied = 0;

    // 业务说明：遍历所有重定位块并修正条目。
    // 输入：current_reloc/reloc_end；输出：total_relocs_applied；规则：仅处理 DIR64；异常：不抛出。
    while (current_reloc < reloc_end && current_reloc->size_of_block > 0) {
        // Base address for this relocation block
        const uint64_t block_base = reinterpret_cast<uint64_t>(payload_image) +
            current_reloc->virtual_address;

        // Get relocation entries (immediately after the block header)
        const auto entries = reinterpret_cast<uint16_t*>(
            reinterpret_cast<uint64_t>(current_reloc) + sizeof(image_base_relocation_t)
        );

        // Calculate number of entries
        const uint32_t entry_count = (current_reloc->size_of_block - sizeof(image_base_relocation_t)) /
            sizeof(uint16_t);

        // 业务说明：遍历当前块内的重定位条目并应用差值。
        // 输入：entries/entry_count；输出：target 地址修正；规则：仅处理 DIR64；异常：不抛出。
        for (uint32_t i = 0; i < entry_count; ++i) {
            const uint16_t entry = entries[i];
            const uint16_t type = entry >> 12;
            const uint16_t offset = entry & 0xFFF;

            // Only process DIR64 relocations (standard for 64-bit)
            if (type == IMAGE_REL_BASED_DIR64) {
                // 业务说明：对 64 位指针应用 delta 修正。
                // 输入：target/delta；输出：地址修正；规则：直接加 delta；异常：不抛出。
                // Get pointer to the address that needs relocation
                uint64_t* const target = reinterpret_cast<uint64_t*>(block_base + offset);

                // Apply the delta
                *target += delta;
                total_relocs_applied++;
            }
            else if (type == IMAGE_REL_BASED_ABSOLUTE) {
                // 业务说明：ABSOLUTE 表示填充项，直接跳过。
                // 输入：type；输出：无；规则：continue；异常：不抛出。
                // Padding entry - skip
                continue;
            }
            else {
                // 业务说明：不支持的重定位类型仅记录日志。
                // 输入：type/offset；输出：日志；规则：不终止；异常：不抛出。
                // Unsupported relocation type
                logs::print("[Loader] Warning: Unsupported relocation type %d at offset 0x%x\n",
                    type, offset);
            }
        }

        // Move to next relocation block
        current_reloc = reinterpret_cast<image_base_relocation_t*>(
            reinterpret_cast<uint64_t>(current_reloc) + current_reloc->size_of_block
        );
    }

    logs::print("[Loader] Applied %d DIR64 relocations\n", total_relocs_applied);
    return true;
}

} // namespace loader
