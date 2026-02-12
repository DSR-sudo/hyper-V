#include "driver_instrumentation.h"
#include "../kernel_scan/kernel_scan.h"
#include "../../arch/arch.h"
#include "../../crt/crt.h"
#include "../../logs/logs.h"
#include "../../memory_manager/memory_manager.h"
#include "../../scan/scan.h"
#include "../../slat/cr3/cr3.h"
#include "../../slat/cr3/pte.h"
#include "../../slat/slat.h"
#include "../../loader/pe.h"
#include "../../loader/reloc.h"
#include "../../loader/imports.h"
#include "../../loader/cookie.h"
#include "../../structures/virtual_address.h"
#include "../../../../shared/structures/trap_frame.h"
#include "../../../../shared/payload/payload_bin.h"

namespace business::driver_instrumentation {
namespace {
std::uint64_t g_ntoskrnl_base = 0;
std::uint64_t g_mm_allocate_independent_pages_ex = 0;
std::uint64_t g_trampoline_entry = 0;
std::uint8_t g_trampoline_ept_applied = 0;
std::uint8_t g_hijack_state = 0;
std::uint8_t g_hijack_completed = 0;
std::uint64_t g_trampoline_guest_physical = 0;
std::uint8_t g_trampoline_original_execute_access = 1;
trap_frame_t g_saved_trap_frame = {};
std::uint64_t g_saved_rsp = 0;
std::uint64_t g_saved_rip = 0;
std::uint8_t g_saved_stack[0x200] = {};
std::uint32_t g_saved_stack_size = sizeof(g_saved_stack);
std::uint64_t g_mm_alloc_result = 0;
std::uint64_t g_mm_alloc_size = 0x1000;
std::uint8_t g_scan_buffer[0x1008] = {};
std::uint8_t g_payload_loaded = 0;
std::uint64_t g_payload_target_base = 0;
std::uint32_t g_payload_image_size = 0;
constexpr std::uint32_t k_payload_buffer_size = 0x20000;
std::uint8_t g_payload_image_buffer[k_payload_buffer_size] = {};
std::uint64_t g_user_vmexit_count = 0;
std::uint64_t g_nt_text_start = 0;
std::uint32_t g_nt_text_size = 0;
std::uint8_t g_scan_wait_log_emitted = 0;
crt::mutex_t g_hijack_mutex = {};
std::uint8_t g_hijack_lock_held = 0;
constexpr std::uint64_t k_rflags_if_mask = 1ull << 9;
std::uint8_t g_ept_window_active = 0;
std::uint32_t g_ept_window_remaining = 0;
constexpr std::uint32_t k_ept_window_instructions = 64;
constexpr std::uint32_t k_ept_window_rearm_gap = 1024;
std::uint32_t g_ept_window_cooldown = 0;
std::uint8_t g_prepare_requested = 0;
std::uint8_t g_prepare_complete = 0;
std::uint8_t g_trigger_requested = 0;
std::uint32_t g_trampoline_arm_vmexit_count = 0;
constexpr std::uint32_t k_trampoline_arm_vmexit_budget = 20000;
std::uint32_t g_ept_window_start_log = 0;
std::uint32_t g_missed_trampoline_log = 0;
std::uint8_t g_force_window_active = 0;
std::uint32_t g_force_window_remaining = 0;
constexpr std::uint32_t k_force_window_instructions = 256;

bool read_guest_memory(const std::uint64_t guest_virtual_address,
                       void *const buffer, const std::uint64_t size);
bool write_guest_memory(const std::uint64_t guest_virtual_address,
                        const void *const buffer, const std::uint64_t size);

std::uint64_t align_up(const std::uint64_t value,
                       const std::uint64_t alignment) {
  return (value + alignment - 1) & ~(alignment - 1);
}

bool build_payload_image(std::uint32_t *image_size_out) {
  if (!image_size_out) {
    return false;
  }
  const auto nt_headers = loader::get_nt_headers(
      const_cast<std::uint8_t *>(payload::rwbase_image));
  if (!nt_headers) {
    return false;
  }
  const std::uint32_t image_size = nt_headers->optional_header.size_of_image;
  const std::uint32_t headers_size =
      nt_headers->optional_header.size_of_headers;
  if (image_size == 0 || image_size > k_payload_buffer_size) {
    return false;
  }
  if (headers_size == 0 || headers_size > payload::rwbase_image_size ||
      headers_size > image_size) {
    return false;
  }
  crt::set_memory(g_payload_image_buffer, 0, image_size);
  crt::copy_memory(g_payload_image_buffer, payload::rwbase_image, headers_size);
  auto section = loader::get_first_section(nt_headers);
  for (std::uint16_t i = 0; i < nt_headers->file_header.number_of_sections;
       ++i) {
    const auto &current = section[i];
    if (current.size_of_raw_data == 0) {
      continue;
    }
    if (current.pointer_to_raw_data + current.size_of_raw_data >
        payload::rwbase_image_size) {
      return false;
    }
    if (current.virtual_address + current.size_of_raw_data > image_size) {
      return false;
    }
    const auto *raw = reinterpret_cast<const std::uint8_t *>(payload::rwbase_image)
        + current.pointer_to_raw_data;
    crt::copy_memory(g_payload_image_buffer + current.virtual_address, raw,
                     current.size_of_raw_data);
  }
  *image_size_out = image_size;
  return true;
}

bool load_payload_into_guest() {
  if (g_payload_loaded != 0) {
    return true;
  }
  if (g_mm_alloc_result == 0 || g_ntoskrnl_base == 0) {
    return false;
  }
  std::uint32_t image_size = 0;
  if (!build_payload_image(&image_size)) {
    logs::print("[Payload] Build failed\n");
    return false;
  }
  if (!loader::apply_relocations(g_payload_image_buffer, g_mm_alloc_result)) {
    logs::print("[Payload] Relocation failed\n");
    return false;
  }
  if (!loader::resolve_payload_imports(g_payload_image_buffer,
                                       g_ntoskrnl_base)) {
    logs::print("[Payload] Import resolve failed\n");
    return false;
  }
  if (!loader::fix_security_cookie(g_payload_image_buffer,
                                   g_mm_alloc_result)) {
    logs::print("[Payload] Security cookie fix failed\n");
    return false;
  }
  if (!write_guest_memory(g_mm_alloc_result, g_payload_image_buffer,
                          image_size)) {
    logs::print("[Payload] Write to guest failed\n");
    return false;
  }
  g_payload_loaded = 1;
  g_payload_target_base = g_mm_alloc_result;
  g_payload_image_size = image_size;
  const auto entry_rva = loader::get_entry_point_rva(g_payload_image_buffer);
  logs::print("[Payload] Mapped base: 0x%p, size: 0x%x, entry: 0x%p\n",
              g_payload_target_base, g_payload_image_size,
              g_payload_target_base + entry_rva);
  return true;
}

std::uint64_t request_prepare_internal() {
  if (g_hijack_completed != 0) {
    g_hijack_completed = 0;
    g_hijack_state = 0;
    g_trampoline_ept_applied = 0;
    g_ept_window_active = 0;
    g_ept_window_remaining = 0;
    g_ept_window_cooldown = 0;
  }
  g_prepare_requested = 1;
  g_prepare_complete = 0;
  g_scan_wait_log_emitted = 0;
  logs::print("[Hijack] Prepare requested\n");
  return 1;
}

std::uint64_t request_trigger_internal() {
  if (g_hijack_completed != 0) {
    g_hijack_completed = 0;
    g_hijack_state = 0;
    g_trampoline_ept_applied = 0;
    g_ept_window_active = 0;
    g_ept_window_remaining = 0;
    g_ept_window_cooldown = 0;
  }
  g_trigger_requested = 1;
  g_scan_wait_log_emitted = 0;
  g_force_window_active = 1;
  g_force_window_remaining = k_force_window_instructions;
  logs::print("[Hijack] Trigger requested\n");
  return 1;
}

bool read_guest_memory(const std::uint64_t guest_virtual_address,
                       void *const buffer, const std::uint64_t size) {
  if (!guest_virtual_address || !buffer || size == 0) {
    return false;
  }
  const cr3 guest_cr3 = arch::get_guest_cr3();
  const cr3 slat_cr3 = slat::hyperv_cr3();
  return memory_manager::operate_on_guest_virtual_memory(
             slat_cr3, buffer, guest_virtual_address, guest_cr3, size,
             memory_operation_t::read_operation) == size;
}

bool write_guest_memory(const std::uint64_t guest_virtual_address,
                        const void *const buffer, const std::uint64_t size) {
  if (!guest_virtual_address || !buffer || size == 0) {
    return false;
  }
  const cr3 guest_cr3 = arch::get_guest_cr3();
  const cr3 slat_cr3 = slat::hyperv_cr3();
  return memory_manager::operate_on_guest_virtual_memory(
             slat_cr3, const_cast<void *>(buffer), guest_virtual_address,
             guest_cr3, size,
             memory_operation_t::write_operation) == size;
}

bool apply_trampoline_ept_trap() {
  if (!g_trampoline_guest_physical || g_trampoline_ept_applied != 0) {
    return false;
  }
  if (slat::hook_cr3().flags == 0) {
    slat::set_up_hook_cr3();
  }
  const virtual_address_t target_physical = {
      .address = g_trampoline_guest_physical};
  slat_pte *const target_pte =
      slat::get_pte(slat::hook_cr3(), target_physical, 1);
  if (!target_pte) {
    return false;
  }
  g_trampoline_original_execute_access =
      static_cast<std::uint8_t>(target_pte->execute_access);
  target_pte->execute_access = 0;
  slat::invept_single_context(slat::hook_cr3());
  g_trampoline_ept_applied = 1;
  g_ept_window_active = 1;
  g_ept_window_remaining = k_ept_window_instructions;
  g_trampoline_arm_vmexit_count = 0;
  return true;
}

bool restore_trampoline_ept_trap() {
  if (!g_trampoline_guest_physical || g_trampoline_ept_applied == 0) {
    return false;
  }
  const virtual_address_t target_physical = {
      .address = g_trampoline_guest_physical};
  slat_pte *const target_pte =
      slat::get_pte(slat::hook_cr3(), target_physical, 1);
  if (!target_pte) {
    return false;
  }
  target_pte->execute_access = g_trampoline_original_execute_access;
  slat::invept_single_context(slat::hook_cr3());
  g_trampoline_ept_applied = 2;
  g_ept_window_active = 0;
  g_ept_window_remaining = 0;
  g_trampoline_arm_vmexit_count = 0;
  arch::disable_mtf();
  return true;
}

void save_guest_stack(const std::uint64_t rsp) {
  g_saved_rsp = rsp;
  if (rsp != 0) {
    read_guest_memory(rsp, g_saved_stack, g_saved_stack_size);
  }
}

void restore_guest_stack() {
  if (g_saved_rsp != 0) {
    write_guest_memory(g_saved_rsp, g_saved_stack, g_saved_stack_size);
  }
}

void prepare_mm_alloc_call(trap_frame_t *const trap_frame) {
  const std::uint64_t original_rsp = arch::get_guest_rsp();
  g_saved_rip = arch::get_guest_rip();
  save_guest_stack(original_rsp);
  g_saved_trap_frame = *trap_frame;
  std::uint64_t new_rsp = original_rsp - 0x80;
  new_rsp &= ~0xFULL;
  if (((new_rsp + 8) & 0xFULL) != 0) {
    new_rsp -= 8;
  }
  const std::uint64_t return_address = g_trampoline_entry;
  write_guest_memory(new_rsp, &return_address, sizeof(return_address));
  std::uint64_t stack_slots[7] = {};
  write_guest_memory(new_rsp + 8, stack_slots, sizeof(stack_slots));
  trap_frame->rcx = g_mm_alloc_size;
  trap_frame->rdx = 0;
  trap_frame->r8 = 0;
  trap_frame->r9 = 0;
  trap_frame->rsp = new_rsp;
  arch::set_guest_rsp(new_rsp);
  arch::set_guest_rip(g_mm_allocate_independent_pages_ex);
}

bool try_resolve_kernel_targets() {
  if (g_ntoskrnl_base == 0) {
    return false;
  }
  if (g_nt_text_start == 0 || g_nt_text_size == 0) {
    if (kernel_scan::get_ntoskrnl_text_range(
            g_ntoskrnl_base, &g_nt_text_start, &g_nt_text_size,
            &read_guest_memory)) {
      logs::print("[Scan] Ntoskrnl exec: 0x%p - 0x%p\n", g_nt_text_start,
                  g_nt_text_start + g_nt_text_size);
    }
  }
  if (g_nt_text_start == 0 || g_nt_text_size == 0) {
    return false;
  }
  if (g_mm_allocate_independent_pages_ex == 0) {
    const char *signature =
        "41 8B D6 B9 00 10 00 00 E8 ? ? ? ? 48 8B D8";
    g_mm_allocate_independent_pages_ex =
        scan::find_function(slat::hyperv_cr3(), arch::get_guest_cr3(),
                            g_ntoskrnl_base, signature);
    if (g_mm_allocate_independent_pages_ex != 0) {
      logs::print("[Scan] MmAllocateIndependentPagesEx: 0x%p\n",
                  g_mm_allocate_independent_pages_ex);
    } else {
      logs::print("[Scan] MmAllocateIndependentPagesEx not found\n");
      return false;
    }
  }
  if (g_trampoline_entry == 0) {
    const char *target_name = "NtOpenFile";
    g_trampoline_entry =
        loader::get_kernel_export(g_ntoskrnl_base, target_name);
    if (g_trampoline_entry == 0) {
      target_name = "IoCreateDevice";
      g_trampoline_entry =
          loader::get_kernel_export(g_ntoskrnl_base, target_name);
    }
    if (g_trampoline_entry == 0) {
      logs::print("[Scan] Trampoline export not found\n");
      return false;
    }
    logs::print("[Scan] Trampoline %s: 0x%p\n", target_name,
                g_trampoline_entry);
  }
  if (g_trampoline_entry < g_nt_text_start ||
      g_trampoline_entry >= g_nt_text_start + g_nt_text_size) {
    logs::print("[Scan] Trampoline out of .text range\n");
    g_trampoline_entry = 0;
    return false;
  }
  if (g_trampoline_guest_physical == 0) {
    if (arch::get_guest_cpl() > 0) {
      return false;
    }
    const cr3 guest_cr3 = arch::get_guest_cr3();
    const cr3 slat_cr3 = slat::hyperv_cr3();
    const virtual_address_t trampoline_va = {.address = g_trampoline_entry};
    g_trampoline_guest_physical = memory_manager::translate_guest_virtual_address(
        guest_cr3, slat_cr3, trampoline_va);
    if (g_trampoline_guest_physical == 0) {
      logs::print("[Scan] Trampoline physical resolve failed\n");
      return false;
    }
  }
  return true;
}
} // namespace

std::uint64_t request_prepare() {
  return request_prepare_internal();
}

std::uint64_t request_trigger() {
  return request_trigger_internal();
}

void on_first_vmexit(std::uint64_t ntoskrnl_base) {
  g_ntoskrnl_base = ntoskrnl_base;
  if (g_ntoskrnl_base == 0) {
    return;
  }
  const auto payload_image_size =
      loader::get_size_of_image(const_cast<std::uint8_t *>(payload::rwbase_image));
  if (payload_image_size != 0) {
    g_mm_alloc_size = align_up(payload_image_size, 0x1000);
  }
}

bool on_vmexit(std::uint64_t exit_reason, trap_frame_t *trap_frame) {
  if (!trap_frame) {
    return false;
  }
  const std::uint8_t guest_cpl = arch::get_guest_cpl();
  const std::uint64_t guest_rflags = arch::get_guest_rflags();
  const bool interrupts_enabled =
      (guest_rflags & k_rflags_if_mask) == k_rflags_if_mask;
  const cr3 guest_cr3 = arch::get_guest_cr3();
  if (guest_cpl > 0) {
    ++g_user_vmexit_count;
  }
  if (g_hijack_completed == 0 && g_trampoline_ept_applied == 0 &&
      g_ntoskrnl_base != 0 &&
      (g_prepare_requested == 1 || g_trigger_requested == 1)) {
    const bool allow_kernel_window =
        guest_cpl == 0 && (interrupts_enabled || g_trigger_requested == 1);
    if (allow_kernel_window) {
      if (g_hijack_lock_held == 0 && g_hijack_mutex.try_lock()) {
        g_hijack_lock_held = 1;
      }
      if (g_hijack_lock_held == 1) {
        if (try_resolve_kernel_targets()) {
          g_prepare_complete = 1;
          if (g_prepare_requested == 1) {
            g_prepare_requested = 0;
          }
          if (g_trigger_requested == 1 && g_prepare_complete == 1) {
            if (apply_trampoline_ept_trap()) {
              logs::print("[Hijack] Trampoline EPT trap armed at 0x%p\n",
                          g_trampoline_entry);
              g_ept_window_start_log = 0;
              g_missed_trampoline_log = 0;
            } else {
              logs::print("[Hijack] EPT trap arm failed\n");
            }
            g_trigger_requested = 0;
          }
        } else if (g_scan_wait_log_emitted == 0) {
          logs::print("[Scan] Waiting for stable targets\n");
          g_scan_wait_log_emitted = 1;
        }
        if (g_trampoline_ept_applied == 0 && g_hijack_completed == 0) {
          g_hijack_mutex.release();
          g_hijack_lock_held = 0;
        }
      }
    } else if (g_scan_wait_log_emitted == 0) {
      logs::print("[Scan] Waiting for kernel CPL0 + IF\n");
      g_scan_wait_log_emitted = 1;
    }
  }
  if (g_hijack_completed == 0 && g_hijack_state == 0 &&
      g_trampoline_ept_applied == 0 && g_prepare_complete == 1 &&
      g_trigger_requested == 1 && g_trampoline_guest_physical != 0) {
    if (apply_trampoline_ept_trap()) {
      logs::print("[Hijack] Trampoline EPT trap armed at 0x%p\n",
                  g_trampoline_entry);
      g_ept_window_start_log = 0;
      g_missed_trampoline_log = 0;
    } else {
      logs::print("[Hijack] EPT trap arm failed\n");
    }
    g_trigger_requested = 0;
  }
  if (g_trampoline_ept_applied == 1 && g_hijack_state == 0 &&
      g_force_window_active == 1) {
    if (arch::is_mtf_exit(exit_reason) == 1) {
      if (g_force_window_remaining > 0) {
        --g_force_window_remaining;
      }
      if (g_force_window_remaining == 0) {
        slat::set_cr3(slat::hyperv_cr3());
        arch::disable_mtf();
        g_force_window_active = 0;
      } else {
        slat::set_cr3(slat::hook_cr3());
        arch::enable_mtf();
      }
      return true;
    }
    if (guest_cpl == 0) {
      slat::set_cr3(slat::hook_cr3());
      arch::enable_mtf();
    }
  }
  if (g_trampoline_ept_applied == 1 && g_hijack_state == 0 &&
      g_ept_window_active == 1) {
    if (g_trampoline_arm_vmexit_count < UINT32_MAX) {
      ++g_trampoline_arm_vmexit_count;
    }
    if (g_ept_window_start_log == 0) {
      logs::print("[Hijack] EPT window active, waiting for trampoline\n");
      g_ept_window_start_log = 1;
    }
    if (g_trampoline_arm_vmexit_count >= k_trampoline_arm_vmexit_budget) {
      restore_trampoline_ept_trap();
      slat::set_cr3(slat::hyperv_cr3());
      g_trigger_requested = 0;
      g_prepare_complete = 1;
      g_force_window_active = 0;
      g_force_window_remaining = 0;
      logs::print("[Hijack] EPT trap timeout, disarmed after %d VMEXIT\n",
                  k_trampoline_arm_vmexit_budget);
      return false;
    }
    if (arch::is_mtf_exit(exit_reason) == 1) {
      if (g_ept_window_remaining > 0) {
        --g_ept_window_remaining;
      }
      if (g_ept_window_remaining == 0) {
        slat::set_cr3(slat::hyperv_cr3());
        arch::disable_mtf();
        g_ept_window_active = 0;
        g_ept_window_cooldown = k_ept_window_rearm_gap;
      } else {
        slat::set_cr3(slat::hook_cr3());
        arch::enable_mtf();
      }
      return true;
    }
    if (guest_cpl == 0 && interrupts_enabled) {
      slat::set_cr3(slat::hook_cr3());
      arch::enable_mtf();
    }
  }
  if (g_trampoline_ept_applied == 1 && g_hijack_state == 0 &&
      g_ept_window_active == 0 && g_ept_window_cooldown > 0) {
    --g_ept_window_cooldown;
  }
  if (g_trampoline_ept_applied == 1 && g_hijack_state == 0 &&
      g_ept_window_active == 0 && g_ept_window_cooldown == 0 &&
      guest_cpl == 0 && interrupts_enabled) {
    g_ept_window_active = 1;
    g_ept_window_remaining = k_ept_window_instructions;
    slat::set_cr3(slat::hook_cr3());
    arch::enable_mtf();
  }
  if (arch::is_slat_violation(exit_reason) != 1) {
    return false;
  }
  const auto qualification = arch::get_exit_qualification();
  const std::uint64_t guest_rip = arch::get_guest_rip();
  const std::uint64_t guest_physical = arch::get_guest_physical_address();
  if (g_trampoline_ept_applied == 1 && g_hijack_state == 0 &&
      g_ept_window_active == 1) {
    const bool is_target =
        qualification.caused_by_translation &&
        qualification.execute_access &&
        g_trampoline_guest_physical != 0 &&
        guest_physical == g_trampoline_guest_physical &&
        guest_rip == g_trampoline_entry;
    if (!is_target) {
      if (g_missed_trampoline_log < 3) {
        logs::print("[Hijack] EPT miss: RIP=0x%p GPA=0x%p\n", guest_rip,
                    guest_physical);
        ++g_missed_trampoline_log;
      }
      slat::set_cr3(slat::hyperv_cr3());
      arch::enable_mtf();
      g_ept_window_active = 1;
      g_ept_window_remaining = 1; // Re-arm on next MTF exit
      g_ept_window_cooldown = 0;
      return false;
    }
  }
  if (g_trampoline_ept_applied != 0 &&
      qualification.caused_by_translation &&
      qualification.execute_access &&
      g_trampoline_guest_physical != 0 &&
      guest_physical == g_trampoline_guest_physical &&
      guest_rip == g_trampoline_entry &&
      g_mm_allocate_independent_pages_ex != 0) {
    if (g_hijack_state == 0) {
      g_ept_window_active = 0;
      g_ept_window_remaining = 0;
      g_force_window_active = 0;
      g_force_window_remaining = 0;
      arch::disable_mtf();
      prepare_mm_alloc_call(trap_frame);
      g_hijack_state = 1;
      return true;
    }
    if (g_hijack_state == 1) {
      g_mm_alloc_result = trap_frame->rax;
      if (g_mm_alloc_result != 0) {
        if (!load_payload_into_guest()) {
          logs::print("[Payload] Load failed\n");
        }
      } else {
        logs::print("[Payload] MmAllocateIndependentPagesEx failed\n");
      }
      restore_guest_stack();
      *trap_frame = g_saved_trap_frame;
      restore_trampoline_ept_trap();
      slat::set_cr3(slat::hyperv_cr3());
      arch::set_guest_rsp(g_saved_rsp);
      arch::set_guest_rip(g_saved_rip);
      g_hijack_state = 2;
      g_hijack_completed = 1;
      if (g_hijack_lock_held == 1) {
        g_hijack_mutex.release();
        g_hijack_lock_held = 0;
      }
      return true;
    }
  }
  return false;
}

} // namespace business::driver_instrumentation
