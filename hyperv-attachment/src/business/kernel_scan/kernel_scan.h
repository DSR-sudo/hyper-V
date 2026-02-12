#pragma once
#include <cstdint>

namespace business::kernel_scan {
using read_guest_memory_fn =
    bool (*)(std::uint64_t, void *, std::uint64_t);

bool get_ntoskrnl_text_range(std::uint64_t ntoskrnl_base,
                             std::uint64_t *text_start,
                             std::uint32_t *text_size,
                             read_guest_memory_fn read_guest);

bool find_call_to_target(std::uint64_t text_start, std::uint32_t text_size,
                         std::uint64_t target,
                         read_guest_memory_fn read_guest,
                         std::uint8_t *scratch,
                         std::uint32_t scratch_size,
                         std::uint64_t *call_address_out);

std::uint64_t find_function_start_around(std::uint64_t text_start,
                                         std::uint32_t text_size,
                                         std::uint64_t address,
                                         read_guest_memory_fn read_guest,
                                         std::uint8_t *scratch,
                                         std::uint32_t scratch_size);

std::uint64_t resolve_iop_load_driver(std::uint64_t ntoskrnl_base,
                                      std::uint64_t mm_allocate_addr,
                                      read_guest_memory_fn read_guest,
                                      std::uint8_t *scan_scratch,
                                      std::uint32_t scan_scratch_size,
                                      std::uint8_t *prologue_scratch,
                                      std::uint32_t prologue_scratch_size);

} // namespace business::kernel_scan
