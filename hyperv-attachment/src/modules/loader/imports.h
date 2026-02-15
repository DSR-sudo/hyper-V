#pragma once
// =============================================================================
// VMM Shadow Mapper - Import Resolver
// Ported from kdmapper::ResolveImports + GetKernelModuleExport
// =============================================================================

#include <cstdint>
#include <cstddef>

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

/**
 * @description 在内核模块内执行特征码扫描。
 * @param {uint64_t} module_base 模块基址。
 * @param {size_t} module_size 模块大小。
 * @param {const char*} pattern 特征码字节序列。
 * @param {const char*} mask 特征码掩码。
 * @return {uint64_t} 匹配地址，失败返回 0。
 * @throws {无} 不抛出异常。
 * @example
 * const auto addr = find_pattern_in_module(base, size, pat, mask);
 */
uint64_t find_pattern_in_module(uint64_t module_base, size_t module_size, const char* pattern, const char* mask);

/**
 * @description 解析 MmAllocateIndependentPagesEx 的内核地址。
 * @param {uint64_t} ntoskrnl_base ntoskrnl 基址。
 * @return {uint64_t} 解析后的函数地址，失败返回 0。
 * @throws {无} 不抛出异常。
 * @example
 * const auto addr = resolve_mm_allocate_independent_pages_ex(nt_base);
 */
uint64_t resolve_mm_allocate_independent_pages_ex(uint64_t ntoskrnl_base);

// String comparison helper (no CRT dependency)
int str_compare(const char* s1, const char* s2);
int str_compare_insensitive(const char* s1, const char* s2);

} // namespace loader
