#include "scan.h"
#include "../crt/crt.h"
#include "../logs/logs.h"
#include "../memory_manager/heap_manager.h" // Fix: Include heap_manager
#include "../memory_manager/memory_manager.h"
#include "../slat/cr3/cr3.h" // Fix: Include slat::cr3
#include "../slat/slat.h"
#include "guest.h"
#include "pe.h"

namespace loader {
namespace scan {

// Local helper for case-insensitive string comparison
// Returns 0 if strings are equal (case-insensitive)
static int str_compare_insensitive(const char *s1, const char *s2) {
  while (*s1 && *s2) {
    char c1 = *s1;
    char c2 = *s2;
    // Simple validation: ASCII only
    if (c1 >= 'A' && c1 <= 'Z')
      c1 += 32;
    if (c2 >= 'A' && c2 <= 'Z')
      c2 += 32;

    if (c1 != c2)
      return c1 - c2;
    s1++;
    s2++;
  }
  return *s1 - *s2;
}

// Helper: Reads guest virtual memory using current discovery CR3s
static bool read_guest_virt(uint64_t va, void *buffer, uint32_t size) {
  return loader::read_guest_memory_explicit(va, buffer, size,
                                            loader::get_discovery_cr3(),
                                            loader::get_discovery_slat_cr3());
}

// Helper: translate guest VA to PA for result
static uint64_t translate_guest_va(uint64_t va) {
  return memory_manager::translate_guest_virtual_address(
      loader::get_discovery_cr3(), loader::get_discovery_slat_cr3(),
      {.address = va});
}

// Context for module enumeration check
struct scan_ctx_t {
  uint32_t needed_size;
  uint64_t result_pa;
  uint64_t result_va;
};

// Callback called for each module found in Guest
static bool scan_module_callback(const guest_module_info_t *info,
                                 void *context) {
  logs::print("[Scan] Module found: %s at 0x%p\n", info->name,
              info->base_address);
  auto *ctx = static_cast<scan_ctx_t *>(context);

  // Security/Stability filters
  // Skip critical DLLs to reduce risk, but ALLOW ntoskrnl.exe (safest for
  // codecave)
  if (str_compare_insensitive(info->name, "hal.dll") == 0 ||
      str_compare_insensitive(info->name, "kd.dll") == 0 ||
      str_compare_insensitive(info->name, "ci.dll") == 0 ||
      str_compare_insensitive(info->name, "clipsp.sys") == 0) {
    return true; // Continue search
  }

  // Read DOS header
  image_dos_header_t dos;
  if (!read_guest_virt(info->base_address, &dos, sizeof(dos)))
    return true;
  if (dos.e_magic != 0x5A4D)
    return true;

  // Read NT headers
  image_nt_headers64_t nt;
  if (!read_guest_virt(info->base_address + dos.e_lfanew, &nt, sizeof(nt)))
    return true;
  if (nt.signature != 0x00004550)
    return true;

  // Iterate sections
  // We need to read section headers. They are after OptionalHeader.
  // Location = Base + e_lfanew + sizeof(Signature) + sizeof(FileHeader) +
  // SizeOfOptionalHeader But cleaner: IMAGE_FIRST_SECTION logic

  uint64_t section_headers_offset =
      info->base_address + dos.e_lfanew + sizeof(uint32_t) + // Signature
      sizeof(image_file_header_t) + nt.file_header.size_of_optional_header;

  // Allocate buffer for section headers
  uint32_t sections_size =
      nt.file_header.number_of_sections * sizeof(image_section_header_t);
  // Using stack buffer if small enough, or heap. sections are usually few.
  // Max sections usually < 96. 96 * 40 = ~4KB. Let's use heap to be safe on
  // stack.

  auto *sections = static_cast<image_section_header_t *>(
      heap_manager::allocate_page()); // 4KB is enough for ~100 sections
  if (!sections)
    return true;

  if (!read_guest_virt(section_headers_offset, sections, sections_size)) {
    // heap_manager doesn't have free? We can't free in this simplified manager
    // easily if page based. Assuming linear allocator.
    return true;
  }

  // Scan sections
  for (uint16_t i = 0; i < nt.file_header.number_of_sections; i++) {
    const auto &sec = sections[i];

    // Filter: Must be Executable, Not Discardable, and Contains CODE (0x20)
    // Characteristics & IMAGE_SCN_MEM_EXECUTE (0x20000000)
    // Characteristics & IMAGE_SCN_MEM_DISCARDABLE (0x02000000)
    // Characteristics & IMAGE_SCN_CNT_CODE (0x00000020)

    // Only scan for codecave if we haven't found one yet
    // Filter: Must be Executable, Not Discardable.
    // We removed CNT_CODE (0x20) to find more candidates in drivers.
    if (ctx->result_pa == 0 && (sec.characteristics & 0x20000000) &&
        !(sec.characteristics & 0x02000000)) {

      // We scan this section
      uint64_t sec_start_va = info->base_address + sec.virtual_address;
      uint32_t sec_size = sec.virtual_size; // VirtualSize is used for mapping

      // [NEW] Slack Space Scanning
      // Standard PE sections are page-aligned in memory.
      // Unused space at the end of the last page is zero-filled but mapped as
      // Executable.
      uint64_t sec_end_va = sec_start_va + sec_size;
      uint64_t sec_end_aligned = (sec_end_va + 0xFFF) & ~0xFFF;
      uint64_t slack_size = sec_end_aligned - sec_end_va;

      if (slack_size >= ctx->needed_size) {
        // We found a perfect empty space at the end of the section!
        // It's safe because it's outside VirtualSize data but inside the mapped
        // Page.
        uint64_t found_va = sec_end_va; // Start of slack
        // Align 16 bytes for safety
        if (found_va % 16 != 0) {
          found_va = (found_va + 15) & ~15;
          if (sec_end_aligned - found_va < ctx->needed_size)
            found_va = 0; // Not enough after alignment
        }

        if (found_va) {
          uint64_t pa = translate_guest_va(found_va);
          if (pa) {
            ctx->result_pa = pa;
            ctx->result_va = found_va;
            logs::print("[Scan] Found Slack Space in %s at VA:0x%p (PA:0x%p) "
                        "Size:0x%x\n",
                        info->name, found_va, pa, slack_size);
            return true;
          }
        }
      }

      // Read section content chunk by chunk
      // Scanning for 0xCC padding.
      uint32_t consecutive_cc = 0;
      // Global index in section
      for (uint32_t offset = 0; offset < sec_size; offset += 0x200) {
        uint32_t chunk_size = 0x200;
        if (offset + chunk_size > sec_size)
          chunk_size = sec_size - offset;

        uint8_t buffer[0x200]; // Stack buffer (small enough to avoid __chkstk)
        if (!read_guest_virt(sec_start_va + offset, buffer, chunk_size)) {
          consecutive_cc = 0;
          continue;
        }

        for (uint32_t k = 0; k < chunk_size; k++) {
          if (buffer[k] == 0xCC) {
            consecutive_cc++;
          } else {
            consecutive_cc = 0;
          }

          // Check if we found enough
          if (consecutive_cc >= ctx->needed_size) {
            // Calculate VA of the start of this block
            uint64_t found_va =
                (sec_start_va + offset + k) - ctx->needed_size + 1;

            uint64_t pa = translate_guest_va(found_va);
            if (pa) {
              ctx->result_pa = pa;
              ctx->result_va = found_va;

              logs::print("[Scan] Found Codecave in %s at VA:0x%p (PA:0x%p)\n",
                          info->name, found_va, pa);

              // Found one in this module. Return true to continue to NEXT
              // module but stop scanning this one to avoid duplicates.
              return true;
            }
          }
        }
      }
    }
  }

  // Dont free sections, lightweight heap
  return true;
}

scan_result_t find_codecave(uint32_t size, std::uint64_t ntoskrnl_base) {
  if (!loader::g_module_cache.initialized) {
    // Ensure discovery is ready
    loader::set_discovery_cr3(arch::get_guest_cr3());
    loader::set_discovery_slat_cr3(
        slat::hyperv_cr3()); // Requires slat/cr3/cr3.h
    loader::init_guest_discovery(ntoskrnl_base);
  }

  scan_ctx_t ctx = {size, 0, 0};

  logs::print("[Scan] Searching for %d bytes codecave...\n", size);
  loader::enumerate_guest_modules(scan_module_callback, &ctx);

  return {ctx.result_pa, ctx.result_va};
}

void clear_codecave(uint64_t address, uint32_t size) {
  if (!address || size == 0)
    return;

  // Map PA to Host VA to write
  uint64_t size_left = 0;
  void *mapped = memory_manager::map_guest_physical(slat::hyperv_cr3(), address,
                                                    &size_left);

  if (mapped && size_left >= size) {
    crt::set_memory(mapped, 0xCC, size);
    logs::print("[Scan] Cleared codecave at PA:0x%p\n", address);
  } else {
    logs::print("[Scan] Failed to map codecave for clearing (PA:0x%p)\n",
                address);
  }
}

} // namespace scan
} // namespace loader
