#pragma once
#include "../../shared/structures/trap_frame.h"
#include <cstdint>


namespace injection {

class Injector {
public:
  // Main entry point for BSP deployment tasks (Scan, Inject, etc.)
  static void handle_bsp_deployment(trap_frame_t *trap_frame,
                                    uint64_t vmexit_count,
                                    uint64_t ntoskrnl_base);

  // Handles the magic CPUID return (Leaf 0x5000) from shellcode
  static bool handle_shellcode_return(trap_frame_t *trap_frame);

private:
  // Internal helpers
  static void try_inject(trap_frame_t *trap_frame, uint64_t vmexit_count,
                         uint64_t ntoskrnl_base);
  static void inject_minimal_shellcode(trap_frame_t *trap_frame,
                                       uint64_t ex_allocate_pool);
  static void restore_context(trap_frame_t *trap_frame);

  // Deployment State
  static uint8_t scan_done;
  static uint8_t injection_done;
  static uint64_t g_codecave_pa;
  static uint64_t g_codecave_va;

  // Default Context Backup
  static uint64_t g_backup_rip;
  static uint64_t g_backup_rsp;
  static uint64_t g_backup_rflags;
  static trap_frame_t g_backup_context;

  // Retry/Backoff Mechanism
  static uint64_t next_injection_attempt;
};

} // namespace injection
