#pragma once
#include <Library/UefiLib.h>
#include <ia32-doc/ia32_compact.h>

extern UINT64 pml4_physical_allocation;
extern UINT64 pdpt_physical_allocation;

// Task 1.4: Captured kernel base address (from LoaderBlock)
extern UINT64 g_captured_ntoskrnl_base;
extern UINT32 g_captured_ntoskrnl_size;

EFI_STATUS winload_place_hooks(UINT64 image_base, UINT64 image_size);

// Task 1.4: Place OslFwpKernelSetupPhase1 hook to capture kernel base
EFI_STATUS winload_place_kernel_setup_hook(UINT64 image_base, UINT64 image_size);
