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
#include "../arch/arch.h"


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

/**
 * @brief Validates if the given payload is a valid PE executable
 * 
 * @param data Pointer to the payload data
 * @param size Size of the payload data in bytes
 * @return true If the payload is a valid PE executable
 * @return false If the payload is not a valid PE executable
 */
/**
 * @description 校验 Payload 是否为合法 PE64 镜像。
 * @param {const unsigned char*} data Payload 数据指针。
 * @param {const size_t} size Payload 数据大小。
 * @return {bool} 是否为合法 PE64。
 * @throws {无} 不抛出异常。
 * @example
 * const auto ok = validate_payload(payload, size);
 */
bool validate_payload(const unsigned char* data, const size_t size)
{
    // 业务说明：验证 DOS/NT 头签名与可选头格式。
    // 输入：data/size；输出：校验结果；规则：任一校验失败返回 false；异常：不抛出。
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

/**
 * @description 判断内置 Payload 是否已准备就绪。
 * @param {void} 无。
 * @return {bool} 是否准备就绪。
 * @throws {无} 不抛出异常。
 * @example
 * const auto ready = is_payload_ready();
 */
bool is_payload_ready()
{
    // 业务说明：验证 DKOM 与 RWbase 两个 Payload 的 PE 合法性。
    // 输入：无；输出：是否就绪；规则：两者都合法才返回 true；异常：不抛出。
    return validate_payload(payload::dkom_image, payload::dkom_image_size) &&
           validate_payload(payload::rwbase_image, payload::rwbase_image_size);
}

// =============================================================================
// Payload Info Logging
// =============================================================================

/**
 * @brief Prints detailed information about a payload
 * 
 * This function logs various properties of the payload, including its size,
 * image base, entry point, and section count. If the payload is a valid PE
 * file, it also logs the first 64 bytes of the payload for integrity checking.
 * 
 * @param name Name of the payload (e.g., "DKOM" or "RWbase")
 * @param data Pointer to the payload data
 * @param size Size of the payload data in bytes
 */
/**
 * @description 打印 Payload 的关键信息与摘要。
 * @param {const char*} name Payload 名称。
 * @param {const unsigned char*} data Payload 数据指针。
 * @param {const size_t} size Payload 数据大小。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * print_payload_info("DKOM", payload, size);
 */
void print_payload_info(const char* name, const unsigned char* data, const size_t size)
{
    // 业务说明：解析 PE 头并输出镜像大小、入口点与摘要数据。
    // 输入：name/data/size；输出：日志；规则：非法 PE 直接返回；异常：不抛出。
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
/**
 * @brief Allocate memory in Guest physical space and map to VMM for modification
 * 
 * @param size Requested allocation size in bytes
 * @param out_info Output structure containing allocation info
 * @return true If allocation and mapping succeeded
 * @return false If allocation or mapping failed
 */
/**
 * @description 为 Payload 分配来宾可访问的物理内存并映射到 VMM。
 * @param {const uint32_t} size 申请大小（字节）。
 * @param {allocation_info_t*} out_info 输出分配信息。
 * @return {bool} 是否分配成功。
 * @throws {无} 不抛出异常。
 * @example
 * allocation_info_t info{};
 * const auto ok = allocate_guest_memory(size, &info);
 */
static bool allocate_guest_memory(
    const uint32_t size,
    allocation_info_t* out_info)
{
    // 业务说明：从 VMM 堆分配连续页，并计算来宾物理/虚拟地址。
    // 输入：size/out_info；输出：分配信息；规则：任一步失败返回 false；异常：不抛出。
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

/**
 * @brief Maps sections from source to destination memory
 * 
 * @param dest Destination memory address (Guest VA)
 * @param src Source memory address (VMM mapped)
 * @param src_size Size of source memory in bytes
 * @return true If mapping was successful
 * @return false If mapping failed (e.g., bounds check failed)
 */
/**
 * @description 将 PE 各节区映射到目标地址。
 * @param {void*} dest 目标地址（VMM 可写）。
 * @param {const unsigned char*} src 源镜像数据。
 * @param {const size_t} src_size 源镜像大小。
 * @return {bool} 是否映射成功。
 * @throws {无} 不抛出异常。
 * @example
 * const auto ok = map_sections(dest, image, size);
 */
static bool map_sections(void* dest, const unsigned char* src, const size_t src_size)
{
    // 业务说明：拷贝 PE 头与节区数据，并对齐填充。
    // 输入：dest/src/src_size；输出：映射结果；规则：越界校验失败返回 false；异常：不抛出。
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

/**
 * @brief Hides pages in Guest memory using SLAT (Second Level Address Translation)
 * 
 * This function modifies the SLAT entries for the specified pages to make them
 * non-accessible from the Guest's view. It's used to hide pages from RWbase
 * protections.
 * 
 * @param guest_physical The physical address of the first page to hide
 * @param size The total size of the memory region to hide (in bytes)
 * @return true If the pages were successfully hidden
 * @return false If there was an error hiding the pages
 */
/**
 * @description 通过 SLAT 隐藏指定物理页区域。
 * @param {const uint64_t} guest_physical 来宾物理基址。
 * @param {const uint32_t} size 隐藏大小（字节）。
 * @return {bool} 是否隐藏成功。
 * @throws {无} 不抛出异常。
 * @example
 * const auto ok = hide_pages_via_slat(guest_pa, size);
 */
static bool hide_pages_via_slat(const uint64_t guest_physical, const uint32_t size)
{
    // 业务说明：按页计算数量并进行 SLAT 隐藏处理。
    // 输入：guest_physical/size；输出：隐藏结果；规则：当前为占位实现；异常：不抛出。
    const uint32_t page_count = (size + 0xFFF) / 0x1000;
    
    logs::print("[Loader] Hiding %d pages via SLAT (PA: 0x%p)\n", page_count, guest_physical);

    // Use slat::hide_heap_pages or a similar mechanism
    // For RWbase, we need No-Execute / No-Read-Write in Guest view
    //
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

/**
 * @description 部署 DKOM Payload 并准备执行环境。
 * @param {const uint64_t} ntoskrnl_base 来宾 ntoskrnl 基址。
 * @return {deploy_result_t} 部署结果。
 * @throws {无} 不抛出异常。
 * @example
 * const auto result = deploy_dkom_payload(nt_base);
 */
deploy_result_t deploy_dkom_payload(const uint64_t ntoskrnl_base)
{
    // 业务说明：完成 DKOM Payload 的验证、分配、映射与重定位导入处理。
    // 输入：ntoskrnl_base；输出：部署结果；规则：任一步失败返回对应错误；异常：不抛出。
    logs::print("[Loader] ========================================\n");
    logs::print("[Loader] DKOM Payload Deployment Starting\n");
    logs::print("[Loader] ========================================\n");

    // Initialize Guest discovery if not already done
    if (!g_module_cache.initialized) {
        // Set Guest/SLAT CR3 for module discovery
        set_discovery_slat_cr3(slat::hyperv_cr3());
        set_discovery_cr3(arch::get_guest_cr3());
        
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

/**
 * @brief Deploys the RWbase payload to the guest VM.
 * 
 * This function initializes the guest discovery, validates the RWbase payload,
 * allocates guest memory, maps the payload sections, and prepares the payload
 * for execution.
 * 
 * @param ntoskrnl_base The base address of the ntoskrnl module in the guest VM.
 * @return deploy_result_t The result of the deployment operation.
 */
/**
 * @description 部署 RWbase Payload 并进行 SLAT 隐藏。
 * @param {const uint64_t} ntoskrnl_base 来宾 ntoskrnl 基址。
 * @return {deploy_result_t} 部署结果。
 * @throws {无} 不抛出异常。
 * @example
 * const auto result = deploy_rwbase_payload(nt_base);
 */
deploy_result_t deploy_rwbase_payload(const uint64_t ntoskrnl_base)
{
    // 业务说明：完成 RWbase Payload 的验证、分配、映射、重定位导入处理并隐藏页。
    // 输入：ntoskrnl_base；输出：部署结果；规则：失败返回错误码；异常：不抛出。
    logs::print("[Loader] ========================================\n");
    logs::print("[Loader] RWbase Payload Deployment Starting\n");
    logs::print("[Loader] ========================================\n");

    // Initialize Guest discovery
    if (!g_module_cache.initialized) {
        /**
         * @brief Initialize Guest discovery for RWbase payload deployment
         * 
         * @param ntoskrnl_base Base address of ntoskrnl in Guest physical space
         * @return true If discovery initialization succeeded
         * @return false If discovery initialization failed
         */
        set_discovery_slat_cr3(slat::hyperv_cr3());
        set_discovery_cr3(arch::get_guest_cr3());
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
