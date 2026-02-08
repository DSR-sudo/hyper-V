// =============================================================================
// VMM Shadow Mapper - Relocation Engine
// Ported from kdmapper::RelocateImageByDelta
// =============================================================================

#include "reloc.h"
#include "pe.h"
#include "../logs/logs.h"
#include "../crt/crt.h"

namespace loader {

bool apply_relocations(void* payload_image, const uint64_t target_va)
{
    // Get NT headers
    const auto nt_headers = get_nt_headers(payload_image);
    if (!nt_headers) {
        logs::print("[Loader] apply_relocations: Invalid PE headers\n");
        return false;
    }

    // Get relocation directory
    const auto& reloc_dir = nt_headers->optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!reloc_dir.virtual_address || !reloc_dir.size) {
        // No relocations needed - this is valid for PIC code like DKOM
        logs::print("[Loader] apply_relocations: No relocation table (PIC code?)\n");
        return true;
    }

    // Calculate delta (difference between target address and original base)
    const uint64_t original_image_base = nt_headers->optional_header.image_base;
    const int64_t delta = static_cast<int64_t>(target_va) - static_cast<int64_t>(original_image_base);

    if (delta == 0) {
        logs::print("[Loader] apply_relocations: Delta is 0, no relocation needed\n");
        return true;
    }

    logs::print("[Loader] Applying relocations: Original=0x%p, Target=0x%p, Delta=0x%p\n",
        original_image_base, target_va, delta);

    // Get first relocation block
    auto current_reloc = reinterpret_cast<image_base_relocation_t*>(
        reinterpret_cast<uint64_t>(payload_image) + reloc_dir.virtual_address
    );
    
    const auto reloc_end = reinterpret_cast<image_base_relocation_t*>(
        reinterpret_cast<uint64_t>(current_reloc) + reloc_dir.size
    );

    uint32_t total_relocs_applied = 0;

    // Process all relocation blocks
    while (current_reloc < reloc_end && current_reloc->size_of_block > 0) {
        
        // Base address for this relocation block
        const uint64_t block_base = reinterpret_cast<uint64_t>(payload_image) + 
                                     current_reloc->virtual_address;
        
        // Get relocation entries (immediately after the block header)
        const auto entries = reinterpret_cast<uint16_t*>(
            reinterpret_cast<uint64_t>(current_reloc) + sizeof(image_base_relocation_t)
        );
        
        // Calculate number of entries
        const uint32_t entry_count = (current_reloc->size_of_block - sizeof(image_base_relocation_t)) 
                                     / sizeof(uint16_t);

        // Process each relocation entry
        for (uint32_t i = 0; i < entry_count; ++i) {
            const uint16_t entry = entries[i];
            const uint16_t type = entry >> 12;
            const uint16_t offset = entry & 0xFFF;

            // Only process DIR64 relocations (standard for 64-bit)
            if (type == IMAGE_REL_BASED_DIR64) {
                // Get pointer to the address that needs relocation
                uint64_t* const target = reinterpret_cast<uint64_t*>(block_base + offset);
                
                // Apply the delta
                *target += delta;
                total_relocs_applied++;
            }
            else if (type == IMAGE_REL_BASED_ABSOLUTE) {
                // Padding entry - skip
                continue;
            }
            else {
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
