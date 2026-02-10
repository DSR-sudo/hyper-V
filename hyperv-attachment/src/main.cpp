#include "../shared/hypercall/hypercall_def.h"
#include "../shared/structures/trap_frame.h"
#include "arch/arch.h"
#include "crt/crt.h"
#include "hypercall/hypercall.h"
#include "interrupts/interrupts.h"
#include "loader/loader.h"
#include "loader/scan.h"
#include "logs/logs.h"
#include "memory_manager/heap_manager.h"
#include "memory_manager/memory_manager.h"
#include "slat/cr3/cr3.h"
#include "slat/slat.h"
#include "slat/violation/violation.h"
#include <cstdint>
#include <ia32-doc/ia32.hpp>
#include <intrin.h>

typedef std::uint64_t (*vmexit_handler_t)(std::uint64_t a1, std::uint64_t a2,
                                          std::uint64_t a3, std::uint64_t a4);

namespace {
std::uint8_t *original_vmexit_handler = nullptr;
std::uint64_t uefi_boot_physical_base_address = 0;
std::uint64_t uefi_boot_image_size = 0;

std::uint64_t g_image_base = 0;
std::uint64_t g_image_size = 0;
std::uint64_t g_text_start = 0;
std::uint64_t g_text_end = 0;
std::uint64_t g_data_start = 0;
std::uint64_t g_data_end = 0;

// VMM Shadow Mapper: Guest ntoskrnl base address
// TODO: Obtain this from PsLoadedModuleList or Guest CR3 scan
std::uint64_t g_ntoskrnl_base = 0;
} // namespace

void clean_up_uefi_boot_image() {
  const auto mapped_uefi_boot_base = static_cast<std::uint8_t *>(
      memory_manager::map_host_physical(uefi_boot_physical_base_address));
  crt::set_memory(mapped_uefi_boot_base, 0, uefi_boot_image_size);
}

void process_first_vmexit() {
  static std::uint8_t is_first_vmexit = 1;

  if (is_first_vmexit == 1) {
    logs::print("[Runtime] First VMExit captured. Taking control...\n");
    slat::process_first_vmexit();
    interrupts::set_up();
    clean_up_uefi_boot_image();

    // [ARCHITECT] Verify secure kernel export resolution on first boot
    if (g_ntoskrnl_base != 0) {
      const uint64_t pool_api =
          loader::get_kernel_export(g_ntoskrnl_base, "ExAllocatePoolWithTag");
      if (pool_api) {
        logs::print("[Step 1] Success: ExAllocatePoolWithTag = 0x%p\n",
                    pool_api);
      } else {
        logs::print("[Step 1] ERROR: Failed to resolve ExAllocatePoolWithTag "
                    "from 0x%p\n",
                    g_ntoskrnl_base);
      }
    }

    is_first_vmexit = 0;
  }

  if (apic_t::current_apic_id() == 0) {
    static uint8_t has_hidden_heap_pages = 0;
    static uint64_t vmexit_count = 0;

    // VMM Shadow Mapper: Deployment state
    static uint8_t dkom_deployed = 0;
    static uint8_t codecave_scanned = 0; // [NEW] Dedicated scan state
    static uint8_t rwbase_deployed = 0;
    // [DEBUG] Deployment thresholds configured
    constexpr uint64_t DKOM_DEPLOY_THRESHOLD =
        UINT64_MAX; // Stage 1: DKOM (DISABLED)
    constexpr uint64_t SCAN_THRESHOLD =
        150000; // Stage 1.5: Codecave Scan (Lowered)
    constexpr uint64_t HEAP_HIDE_THRESHOLD = UINT64_MAX; // Stage 2: Heap Hide

    ++vmexit_count;

    // [DEBUG] Heartbeat: Verify BSP is counting
    if (vmexit_count % 50000 == 0) {
      logs::print("[Runtime] BSP VMExit Count: %llu\n", vmexit_count);
    }

    // Simplified: ntoskrnl_base is now received only from UEFI/uboot
    // and is already stored in g_ntoskrnl_base.

    // Stage 1: Deploy DKOM (DISABLED)
    if (dkom_deployed == 0 && vmexit_count >= DKOM_DEPLOY_THRESHOLD) {
      if (g_ntoskrnl_base != 0) {
        const auto result = loader::deploy_dkom_payload(g_ntoskrnl_base);
        if (result == loader::deploy_result_t::success) {
          logs::print("[Loader] DKOM deployed successfully\n");
          dkom_deployed = 1; // Only set on success
        } else {
          logs::print("[Loader] DKOM deployment failed: %d (will retry)\n",
                      static_cast<uint32_t>(result));
        }
      }
    }

    // Stage 1.5: Automated Codecave Scan (BSP Only, Post-Init)
    if (codecave_scanned == 0 && vmexit_count >= SCAN_THRESHOLD) {
      if (g_ntoskrnl_base != 0) {
        logs::print(
            "[Runtime] Starting automated Codecave scan (Stage 1.5)...\n");
        // Scan for 100 bytes (example size)
        const uint64_t cave = loader::scan::find_codecave(100, g_ntoskrnl_base);
        if (cave) {
          logs::print("[Runtime] Codecave found at PA: 0x%p\n", cave);
        } else {
          logs::print("[Runtime] Codecave scan failed.\n");
        }
        codecave_scanned =
            1; // Mark as done regardless of result to avoid retry loop
      }
    }

    // Stage 2: Hide heap pages at 1.5M VMExits (After Scan)
    if (has_hidden_heap_pages == 0 && vmexit_count >= HEAP_HIDE_THRESHOLD) {
      has_hidden_heap_pages = slat::hide_heap_pages(slat::hyperv_cr3());

      if (has_hidden_heap_pages == 1) {
        logs::print("[Runtime] Heap memory hiding complete (Total 1.5M VMExits "
                    "threshold met).\n");

        // Stage 3: Deploy RWbase after heap hiding (START3 phase)
        if (rwbase_deployed == 0 && g_ntoskrnl_base != 0) {
          logs::print("[Loader] RWbase deployment - START3 phase\n");
          const auto result = loader::deploy_rwbase_payload(g_ntoskrnl_base);
          if (result == loader::deploy_result_t::success) {
            logs::print("[Loader] RWbase deployed with SLAT hiding\n");
            rwbase_deployed = 1; // Only set on success
          } else {
            logs::print("[Loader] RWbase deployment failed: %d (will retry)\n",
                        static_cast<uint32_t>(result));
          }
        }
      }
    }
  }
}

std::uint64_t do_vmexit_premature_return() {
  return 0; // Intel return
}

std::uint64_t vmexit_handler_detour(const std::uint64_t a1,
                                    const std::uint64_t a2,
                                    const std::uint64_t a3,
                                    const std::uint64_t a4) {
  process_first_vmexit();

  const std::uint64_t exit_reason = arch::get_vmexit_reason();

  // [DEBUG] Manual Trigger logic removed for stability (Integrated into
  // automated flow) Codecave scan will now run as part of the BSP deployment
  // sequence.

  if (arch::is_cpuid(exit_reason) == 1) {
    trap_frame_t *const trap_frame = *reinterpret_cast<trap_frame_t **>(a1);

    const hypercall_info_t hypercall_info = {.value = trap_frame->rcx};

    if (hypercall_info.primary_key == hypercall_primary_key &&
        hypercall_info.secondary_key == hypercall_secondary_key) {
      trap_frame->rsp = arch::get_guest_rsp();
      hypercall::process(hypercall_info, trap_frame);
      arch::set_guest_rsp(trap_frame->rsp);
      arch::advance_guest_rip();
      return do_vmexit_premature_return();
    }
  } else if (arch::is_slat_violation(exit_reason) == 1 &&
             slat::violation::process() == 1) {
    return do_vmexit_premature_return();
  } else if (arch::is_non_maskable_interrupt_exit(exit_reason) == 1) {
    interrupts::process_nmi();
  } else if (arch::is_mtf_exit(exit_reason) == 1) {
    slat::violation::handle_mtf();
    return do_vmexit_premature_return();
  }

  return reinterpret_cast<vmexit_handler_t>(original_vmexit_handler)(a1, a2, a3,
                                                                     a4);
}

#pragma pack(push, 1)
struct image_dos_header {
  std::uint16_t e_magic;
  std::uint8_t _pad[58];
  std::int32_t e_lfanew;
};

struct image_file_header {
  std::uint16_t machine;
  std::uint16_t number_of_sections;
  std::uint32_t time_date_stamp;
  std::uint32_t pointer_to_symbol_table;
  std::uint32_t number_of_symbols;
  std::uint16_t size_of_optional_header;
  std::uint16_t characteristics;
};

struct image_data_directory {
  std::uint32_t virtual_address;
  std::uint32_t size;
};

struct image_optional_header64 {
  std::uint16_t magic;
  std::uint8_t _pad1[66];
  std::uint64_t image_base;
  std::uint32_t section_alignment;
  std::uint32_t file_alignment;
  std::uint8_t _pad2[46];
  std::uint32_t size_of_image;
  std::uint32_t size_of_headers;
  std::uint32_t check_sum;
  std::uint8_t _pad3[10];
  std::uint32_t number_of_rva_and_sizes;
  image_data_directory data_directory[16];
};

struct image_nt_headers64 {
  std::uint32_t signature;
  image_file_header file_header;
  image_optional_header64 optional_header;
};

struct image_section_header {
  std::uint8_t name[8];
  std::uint32_t virtual_size;
  std::uint32_t virtual_address;
  std::uint32_t size_of_raw_data;
  std::uint32_t pointer_to_raw_data;
  std::uint32_t pointer_to_relocations;
  std::uint32_t pointer_to_linenumbers;
  std::uint16_t number_of_relocations;
  std::uint16_t number_of_linenumbers;
  std::uint32_t characteristics;
};
#pragma pack(pop)

void entry_point(std::uint8_t **const vmexit_handler_detour_out,
                 std::uint8_t *const original_vmexit_handler_routine,
                 const std::uint64_t heap_physical_base,
                 const std::uint64_t heap_physical_usable_base,
                 const std::uint64_t heap_total_size,
                 const std::uint64_t _uefi_boot_physical_base_address,
                 const std::uint32_t _uefi_boot_image_size,
                 const std::uint64_t reserved_one,
                 const std::uint64_t ntoskrnl_base_from_uefi) {
  (void)reserved_one; // Intel Only

  // Global Initialization (BSP Only)
  // Prevents race conditions on Heap/Log setup if entry_point is called
  // per-core
  if (apic_t::current_apic_id() == 0) {
    // Task 1.4: Receive ntoskrnl_base captured by uefi-boot from LoaderBlock
    if (ntoskrnl_base_from_uefi != 0) {
      g_ntoskrnl_base = ntoskrnl_base_from_uefi;
    }

    original_vmexit_handler = original_vmexit_handler_routine;
    uefi_boot_physical_base_address = _uefi_boot_physical_base_address;
    uefi_boot_image_size = _uefi_boot_image_size;
    heap_manager::initial_physical_base = heap_physical_base;
    heap_manager::initial_size = heap_total_size;

    *vmexit_handler_detour_out =
        reinterpret_cast<std::uint8_t *>(vmexit_handler_detour);

    const std::uint64_t heap_physical_end =
        heap_physical_base + heap_total_size;
    const std::uint64_t heap_usable_size =
        heap_physical_end - heap_physical_usable_base;

    void *const mapped_heap_usable_base =
        memory_manager::map_host_physical(heap_physical_usable_base);
    heap_manager::set_up(mapped_heap_usable_base, heap_usable_size);

    logs::set_up();

    // [ARCHITECT Phase 2] PE Parsing & Boundary Locking
    const auto image_base = static_cast<std::uint8_t *>(
        memory_manager::map_host_physical(heap_physical_base));
    const auto dos_header = reinterpret_cast<image_dos_header *>(image_base);

    if (dos_header->e_magic == 0x5A4D) {
      const auto nt_headers = reinterpret_cast<image_nt_headers64 *>(
          image_base + dos_header->e_lfanew);
      if (nt_headers->signature == 0x00004550) {
        g_image_base = heap_physical_base;
        g_image_size = nt_headers->optional_header.size_of_image;

        auto section_header = reinterpret_cast<image_section_header *>(
            reinterpret_cast<std::uint8_t *>(&nt_headers->optional_header) +
            nt_headers->file_header.size_of_optional_header);

        logs::print("[Init] Hyper-reV Entry Point reached.\n");
        logs::print("[Init] Heap Physical Base: 0x%p, Size: 0x%p\n",
                    heap_physical_base, heap_total_size);
        logs::print("[Init] UEFI Boot Physical Base: 0x%p, Size: 0x%x\n",
                    _uefi_boot_physical_base_address, _uefi_boot_image_size);

        if (g_ntoskrnl_base != 0) {
          logs::print("[Task 1.4] ntoskrnl_base received from UEFI: 0x%p\n",
                      g_ntoskrnl_base);
        } else {
          logs::print("[Task 1.4] CRITICAL ERROR: ntoskrnl_base not received "
                      "from UEFI. System may be unstable.\n");
        }

        logs::print("[Stealth] PE Image Base: 0x%p\n", g_image_base);
        logs::print("[Stealth] Full Image Range: 0x%p - 0x%p\n", g_image_base,
                    g_image_base + g_image_size);

        for (std::uint32_t i = 0;
             i < nt_headers->file_header.number_of_sections; i++) {
          const auto &section = section_header[i];
          char section_name[9] = {0};
          crt::copy_memory(section_name, section.name, 8);

          logs::print("[Stealth] Section [%s]: 0x%p - 0x%p\n", section_name,
                      heap_physical_base + section.virtual_address,
                      heap_physical_base + section.virtual_address +
                          section.virtual_size);

          if (crt::abs(static_cast<std::int32_t>(section.name[0] - '.')) == 0 &&
              crt::abs(static_cast<std::int32_t>(section.name[1] - 't')) == 0 &&
              crt::abs(static_cast<std::int32_t>(section.name[2] - 'e')) == 0 &&
              crt::abs(static_cast<std::int32_t>(section.name[3] - 'x')) == 0 &&
              crt::abs(static_cast<std::int32_t>(section.name[4] - 't')) == 0) {
            g_text_start = heap_physical_base + section.virtual_address;
            g_text_end = g_text_start + section.virtual_size;
          } else if (crt::abs(static_cast<std::int32_t>(section.name[0] -
                                                        '.')) == 0 &&
                     crt::abs(static_cast<std::int32_t>(section.name[1] -
                                                        'd')) == 0 &&
                     crt::abs(static_cast<std::int32_t>(section.name[2] -
                                                        'a')) == 0 &&
                     crt::abs(static_cast<std::int32_t>(section.name[3] -
                                                        't')) == 0 &&
                     crt::abs(static_cast<std::int32_t>(section.name[4] -
                                                        'a')) == 0) {
            g_data_start = heap_physical_base + section.virtual_address;
            g_data_end = g_data_start + section.virtual_size;
          }
        }
      }
    } else {
      logs::print("[WARNING] PE Parsing failed! Image base not found.\n");
    }

    slat::set_up();
    logs::print("[Init] Component setup complete (Logs, SLAT).\n");
  }
}
