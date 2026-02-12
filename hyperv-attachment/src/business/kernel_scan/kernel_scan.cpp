#include "kernel_scan.h"

namespace business::kernel_scan {

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

static std::uint32_t min_u32(std::uint32_t a, std::uint32_t b) {
  return a < b ? a : b;
}
static std::uint32_t max_u32(std::uint32_t a, std::uint32_t b) {
  return a > b ? a : b;
}


bool get_ntoskrnl_text_range(std::uint64_t ntoskrnl_base,
                             std::uint64_t *text_start,
                             std::uint32_t *text_size,
                             read_guest_memory_fn read_guest) {
  if (!ntoskrnl_base || !text_start || !text_size || !read_guest) {
    return false;
  }
  image_dos_header dos_header = {};
  if (!read_guest(ntoskrnl_base, &dos_header, sizeof(dos_header))) {
    return false;
  }
  if (dos_header.e_magic != 0x5A4D) {
    return false;
  }
  const std::uint64_t nt_headers_address =
      ntoskrnl_base + dos_header.e_lfanew;
  image_nt_headers64 nt_headers = {};
  if (!read_guest(nt_headers_address, &nt_headers, sizeof(nt_headers))) {
    return false;
  }
  if (nt_headers.signature != 0x00004550) {
    return false;
  }
  const std::uint64_t section_headers_address =
      nt_headers_address + sizeof(std::uint32_t) + sizeof(image_file_header) +
      nt_headers.file_header.size_of_optional_header;
  constexpr std::uint32_t k_image_scn_mem_execute = 0x20000000;
  std::uint64_t exec_start = 0;
  std::uint64_t exec_end = 0;
  for (std::uint32_t i = 0; i < nt_headers.file_header.number_of_sections;
       ++i) {
    image_section_header section = {};
    const std::uint64_t section_address =
        section_headers_address + (i * sizeof(image_section_header));
    if (!read_guest(section_address, &section, sizeof(section))) {
      return false;
    }
    if ((section.characteristics & k_image_scn_mem_execute) == 0) {
      continue;
    }
    const std::uint32_t section_size =
        max_u32(section.virtual_size, section.size_of_raw_data);
    if (section_size == 0) {
      continue;
    }
    const std::uint64_t section_start =
        ntoskrnl_base + section.virtual_address;
    const std::uint64_t section_end = section_start + section_size;
    if (exec_start == 0 || section_start < exec_start) {
      exec_start = section_start;
    }
    if (section_end > exec_end) {
      exec_end = section_end;
    }
  }
  if (exec_start == 0 || exec_end <= exec_start) {
    return false;
  }
  *text_start = exec_start;
  *text_size = static_cast<std::uint32_t>(exec_end - exec_start);
  return true;
}

bool find_call_to_target(std::uint64_t text_start, std::uint32_t text_size,
                         std::uint64_t target,
                         read_guest_memory_fn read_guest,
                         std::uint8_t *scratch,
                         std::uint32_t scratch_size,
                         std::uint64_t *call_address_out) {
  if (!text_start || !text_size || !target || !call_address_out || !read_guest ||
      !scratch) {
    return false;
  }
  const std::uint32_t block_size = 0x1000;
  if (scratch_size < block_size + 5) {
    return false;
  }
  for (std::uint32_t offset = 0; offset < text_size; offset += block_size) {
    const std::uint32_t remaining = text_size - offset;
    const std::uint32_t read_size = min_u32(block_size + 5, remaining);
    if (!read_guest(text_start + offset, scratch, read_size)) {
      continue;
    }
    if (read_size < 5) {
      break;
    }
    for (std::uint32_t i = 0; i <= read_size - 5; ++i) {
      if (scratch[i] != 0xE8) {
        continue;
      }
      const std::int32_t rel =
          *reinterpret_cast<const std::int32_t *>(&scratch[i + 1]);
      const std::uint64_t call_site = text_start + offset + i;
      const std::uint64_t call_target = call_site + 5 + rel;
      if (call_target == target) {
        *call_address_out = call_site;
        return true;
      }
    }
  }
  return false;
}


std::uint64_t find_function_start_around(std::uint64_t text_start,
                                         std::uint32_t text_size,
                                         std::uint64_t address,
                                         read_guest_memory_fn read_guest,
                                         std::uint8_t *scratch,
                                         std::uint32_t scratch_size) {
  if (!text_start || !text_size || !address || !read_guest || !scratch) {
    return 0;
  }
  const std::uint64_t range = 0x200;
  const std::uint64_t start =
      address > text_start + range ? address - range : text_start;
  const std::uint32_t size = static_cast<std::uint32_t>(address - start);
  if (size < 4) {
    return address;
  }
  if (scratch_size < size) {
    return address;
  }
  if (!read_guest(start, scratch, size)) {
    return address;
  }
  std::uint64_t best = 0;
  for (std::uint32_t i = 0; i + 4 < size; ++i) {
    if (scratch[i] == 0x40 && scratch[i + 1] == 0x53) {
      best = start + i;
    } else if (scratch[i] == 0x48 && scratch[i + 1] == 0x89 &&
               scratch[i + 2] == 0x5C && scratch[i + 3] == 0x24) {
      best = start + i;
    }
  }
  return best ? best : address;
}

std::uint64_t resolve_iop_load_driver(std::uint64_t ntoskrnl_base,
                                      std::uint64_t mm_allocate_addr,
                                      read_guest_memory_fn read_guest,
                                      std::uint8_t *scan_scratch,
                                      std::uint32_t scan_scratch_size,
                                      std::uint8_t *prologue_scratch,
                                      std::uint32_t prologue_scratch_size) {
  if (!ntoskrnl_base || !mm_allocate_addr || !read_guest) {
    return 0;
  }
  std::uint64_t text_start = 0;
  std::uint32_t text_size = 0;
  if (!get_ntoskrnl_text_range(ntoskrnl_base, &text_start, &text_size,
                               read_guest)) {
    return 0;
  }
  std::uint64_t call_site = 0;
  if (!find_call_to_target(text_start, text_size, mm_allocate_addr, read_guest,
                           scan_scratch, scan_scratch_size, &call_site)) {
    return 0;
  }
  return find_function_start_around(text_start, text_size, call_site,
                                    read_guest, prologue_scratch,
                                    prologue_scratch_size);
}

} // namespace business::kernel_scan
