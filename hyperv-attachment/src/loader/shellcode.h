#pragma once
#include <cstdint>

namespace loader {
namespace shellcode {

// Generates a shellcode buffer to call ExAllocatePoolWithTag
// and return the result via CPUID hypercall.
//
// buffer: Output buffer (must be at least 128 bytes)
// size: Output size of generated shellcode
// ex_allocate_pool: Address of ExAllocatePoolWithTag
// allocation_size: Size of memory to allocate
// tag: Pool tag
void generate_pool_allocation(uint8_t *buffer, uint32_t &size,
                              uint64_t ex_allocate_pool,
                              uint32_t allocation_size, uint32_t tag);

} // namespace shellcode
} // namespace loader
