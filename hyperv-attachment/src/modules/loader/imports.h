#pragma once
// =============================================================================
// VMM Shadow Mapper - Import Resolver
// Ported from kdmapper::ResolveImports + GetKernelModuleExport
// =============================================================================

#include <cstdint>

#include "guest.h"

namespace loader {

// Resolve all imports in a payload image using ntoskrnl and other kernel modules
// @param ctx: Loader context
// @param payload_image: Pointer to the loaded PE image in memory
// @param ntoskrnl_base: Base address of ntoskrnl.exe in Guest kernel space
// @return: true if all imports resolved, false if any import failed
bool resolve_payload_imports(context_t* ctx, void* payload_image, uint64_t ntoskrnl_base);

// Get export address from a kernel module by name
// @param ctx: Loader context
// @param module_base: Base address of the module to search
// @param function_name: Name of the function to find
// @return: Address of the function, or 0 if not found
uint64_t get_kernel_export(context_t* ctx, uint64_t module_base, const char* function_name);

// String comparison helper (no CRT dependency)
int str_compare(const char* s1, const char* s2);
int str_compare_insensitive(const char* s1, const char* s2);

} // namespace loader
