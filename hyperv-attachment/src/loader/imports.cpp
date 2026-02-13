// =============================================================================
// VMM Shadow Mapper - Import Resolver
// Ported from kdmapper::ResolveImports + intel_driver::GetKernelModuleExport
// =============================================================================

#include "imports.h"
#include "pe.h"
#include "guest.h"
#include "../logs/logs.h"
#include "../crt/crt.h"
#include "../arch/arch.h"
#include "../slat/cr3/cr3.h"
#include "../memory_manager/memory_manager.h"

namespace loader {

// =============================================================================
// String Utilities (No CRT)
// =============================================================================

/**
 * @description 比较两个字符串（区分大小写）。
 * @param {const char*} s1 字符串 1。
 * @param {const char*} s2 字符串 2。
 * @return {int} 比较结果差值。
 * @throws {无} 不抛出异常。
 * @example
 * const auto diff = str_compare("a", "b");
 */
int str_compare(const char* s1, const char* s2)
{
    // 业务说明：逐字符比较，直到出现不同或结束。
    // 输入：s1/s2；输出：差值；规则：字节比较；异常：不抛出。
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *reinterpret_cast<const unsigned char*>(s1) - 
           *reinterpret_cast<const unsigned char*>(s2);
}

/**
 * @description 比较两个字符串（忽略大小写）。
 * @param {const char*} s1 字符串 1。
 * @param {const char*} s2 字符串 2。
 * @return {int} 比较结果差值。
 * @throws {无} 不抛出异常。
 * @example
 * const auto diff = str_compare_insensitive("A", "a");
 */
int str_compare_insensitive(const char* s1, const char* s2)
{
    // 业务说明：将字符归一化为小写后比较。
    // 输入：s1/s2；输出：差值；规则：逐字符比较；异常：不抛出。
    while (*s1 && *s2) {
        char c1 = *s1;
        char c2 = *s2;
        
        // Convert to lowercase
        if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
        if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
        
        if (c1 != c2) {
            return c1 - c2;
        }
        s1++;
        s2++;
    }
    return *s1 - *s2;
}

// =============================================================================
// Export Table Resolution (Secure Guest Access)
// =============================================================================

/**
 * @description 从内核模块导出表解析指定函数地址。
 * @param {const uint64_t} module_base 内核模块基址。
 * @param {const char*} function_name 目标函数名。
 * @return {uint64_t} 函数地址，失败返回 0。
 * @throws {无} 不抛出异常。
 * @example
 * const auto addr = get_kernel_export(ntoskrnl_base, "ExAllocatePool");
 */
uint64_t get_kernel_export(const uint64_t module_base, const char* function_name)
{
    // 业务说明：通过来宾内存读取导出表并匹配函数名。
    // 输入：module_base/function_name；输出：函数地址；规则：仅支持非转发导出；异常：不抛出。
    if (!module_base || !function_name) {
        return 0;
    }

    // Capture current Guest context
    const cr3 guest_cr3 = arch::get_guest_cr3();
    const cr3 slat_cr3 = slat::hyperv_cr3();

    // 业务说明：封装来宾虚拟内存读取操作。
    // 输入：gva/buf/size；输出：读取结果；规则：读满才成功；异常：不抛出。
    // Helper: read from Guest virtual memory
    auto read_guest = [&](uint64_t gva, void* buf, uint64_t size) -> bool {
        return memory_manager::operate_on_guest_virtual_memory(
            slat_cr3, buf, gva, guest_cr3, size, memory_operation_t::read_operation
        ) == size;
    };

    // 业务说明：读取并校验 DOS 头。
    // 输入：module_base；输出：dos_header；规则：签名必须匹配；异常：不抛出。
    image_dos_header_t dos_header;
    if (!read_guest(module_base, &dos_header, sizeof(dos_header)) || 
        dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    // 业务说明：读取并校验 NT 头。
    // 输入：module_base；输出：nt_headers；规则：签名必须匹配；异常：不抛出。
    image_nt_headers64_t nt_headers;
    if (!read_guest(module_base + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers)) ||
        nt_headers.signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    // 业务说明：获取导出表目录信息。
    // 输入：nt_headers；输出：export_dir_entry；规则：无导出表返回失败；异常：不抛出。
    const auto& export_dir_entry = nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (export_dir_entry.virtual_address == 0 || export_dir_entry.size == 0) {
        return 0;
    }

    // 业务说明：读取导出表头结构。
    // 输入：module_base/export_dir_entry；输出：export_dir；规则：读取失败返回 0；异常：不抛出。
    image_export_directory_t export_dir;
    if (!read_guest(module_base + export_dir_entry.virtual_address, &export_dir, sizeof(export_dir))) {
        return 0;
    }

    // 业务说明：遍历导出名称表并解析目标函数。
    // 输入：export_dir；输出：函数地址；规则：名称匹配返回地址；异常：不抛出。
    // Local buffers for table addresses
    const uint64_t names_va = module_base + export_dir.address_of_names;
    const uint64_t ordinals_va = module_base + export_dir.address_of_name_ordinals;
    const uint64_t functions_va = module_base + export_dir.address_of_functions;

    for (uint32_t i = 0; i < export_dir.number_of_names; ++i) {
        uint32_t name_rva = 0;
        if (!read_guest(names_va + i * sizeof(uint32_t), &name_rva, sizeof(uint32_t))) {
            continue;
        }

        // Read export name string (max 256 chars for safety)
        char current_name[256] = { 0 };
        if (!read_guest(module_base + name_rva, current_name, sizeof(current_name) - 1)) {
            continue;
        }

        if (str_compare_insensitive(current_name, function_name) == 0) {
            // 业务说明：名称匹配后按序号表解析函数 RVA。
            // 输入：names/ordinals/functions；输出：函数地址；规则：不支持转发导出；异常：不抛出。
            uint16_t ordinal = 0;
            if (!read_guest(ordinals_va + i * sizeof(uint16_t), &ordinal, sizeof(uint16_t))) {
                return 0;
            }

            uint32_t function_rva = 0;
            if (!read_guest(functions_va + ordinal * sizeof(uint32_t), &function_rva, sizeof(uint32_t))) {
                return 0;
            }

            // Check for forwarded export (RVA within export directory range)
            if (function_rva >= export_dir_entry.virtual_address &&
                function_rva < export_dir_entry.virtual_address + export_dir_entry.size) {
                // 业务说明：转发导出暂不支持，直接返回失败。
                // 输入：function_rva；输出：日志；规则：返回 0；异常：不抛出。
                logs::print("[Loader] Warning: Forwarded export '%s' not supported\n", function_name);
                return 0;
            }

            return module_base + function_rva;
        }
    }

    return 0;
}

// =============================================================================
// Import Resolution
// =============================================================================

/**
 * @description 解析并修复 Payload 的导入表。
 * @param {void*} payload_image Payload 镜像基址。
 * @param {const uint64_t} ntoskrnl_base ntoskrnl 基址。
 * @return {bool} 是否解析成功。
 * @throws {无} 不抛出异常。
 * @example
 * const auto ok = resolve_payload_imports(image, nt_base);
 */
bool resolve_payload_imports(void* payload_image, const uint64_t ntoskrnl_base)
{
    // 业务说明：遍历导入表，解析模块与函数并写入 IAT。
    // 输入：payload_image/ntoskrnl_base；输出：解析结果；规则：无法解析则失败；异常：不抛出。
    if (!payload_image || !ntoskrnl_base) {
        logs::print("[Loader] resolve_imports: Invalid parameters\n");
        return false;
    }

    // 业务说明：读取并验证 NT 头。
    // 输入：payload_image；输出：nt_headers；规则：无效返回失败；异常：不抛出。
    const auto nt_headers = get_nt_headers(payload_image);
    if (!nt_headers) {
        logs::print("[Loader] resolve_imports: Invalid PE headers\n");
        return false;
    }

    // 业务说明：读取导入表目录。
    // 输入：nt_headers；输出：import_dir；规则：无导入表直接成功；异常：不抛出。
    const auto& import_dir = nt_headers->optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!import_dir.virtual_address) {
        // No imports - valid for some drivers
        logs::print("[Loader] resolve_imports: No import table\n");
        return true;
    }

    const uint64_t image_base = reinterpret_cast<uint64_t>(payload_image);

    // 业务说明：遍历导入描述符并解析模块。
    // 输入：import_descriptor；输出：modules_resolved/functions_resolved；规则：按模块逐一解析；异常：不抛出。
    auto import_descriptor = reinterpret_cast<image_import_descriptor_t*>(
        image_base + import_dir.virtual_address
    );

    uint32_t modules_resolved = 0;
    uint32_t functions_resolved = 0;

    while (import_descriptor->first_thunk) {
        // Get module name
        const char* module_name = reinterpret_cast<const char*>(
            image_base + import_descriptor->name
        );

        logs::print("[Loader] Resolving imports from: %s\n", module_name);

        // 业务说明：确定导入模块的解析基址。
        // 输入：module_name；输出：resolve_module_base；规则：特定模块有固定策略；异常：不抛出。
        uint64_t resolve_module_base = 0;
        bool module_resolved = false;

        // 业务说明：对关键模块采用特定解析策略。
        // 输入：module_name；输出：resolve_module_base；规则：必要模块必须找到；异常：不抛出。
        if (str_compare_insensitive(module_name, "ntoskrnl.exe") == 0 ||
            str_compare_insensitive(module_name, "ntkrnlmp.exe") == 0 ||
            str_compare_insensitive(module_name, "ntkrnlpa.exe") == 0 ||
            str_compare_insensitive(module_name, "ntkrpamp.exe") == 0) {
            resolve_module_base = ntoskrnl_base;
            module_resolved = true;
        }
        else if (str_compare_insensitive(module_name, "HAL.dll") == 0) {
            // Try to find HAL in loaded modules, fallback to ntoskrnl re-exports
            guest_module_info_t hal_info = {};
            if (find_guest_module("HAL.dll", &hal_info) && hal_info.base_address) {
                resolve_module_base = hal_info.base_address;
                logs::print("[Loader] HAL.dll found at 0x%p\n", resolve_module_base);
            } else {
                // HAL exports are often re-exported by ntoskrnl
                resolve_module_base = ntoskrnl_base;
                logs::print("[Loader] HAL.dll fallback to ntoskrnl re-exports\n");
            }
            module_resolved = true;
        }
        else if (str_compare_insensitive(module_name, "NETIO.SYS") == 0) {
            // CRITICAL: Must find actual NETIO.SYS - no fallback allowed
            guest_module_info_t netio_info = {};
            if (find_guest_module("NETIO.SYS", &netio_info) && netio_info.base_address) {
                resolve_module_base = netio_info.base_address;
                logs::print("[Loader] NETIO.SYS found at 0x%p\n", resolve_module_base);
                module_resolved = true;
            } else {
                logs::print("[Loader] ERROR: NETIO.SYS not found - cannot resolve imports\n");
                return false;
            }
        }
        else if (str_compare_insensitive(module_name, "fwpkclnt.sys") == 0) {
            // Firewall Platform Callout Kernel - required for network filtering
            guest_module_info_t fwp_info = {};
            if (find_guest_module("fwpkclnt.sys", &fwp_info) && fwp_info.base_address) {
                resolve_module_base = fwp_info.base_address;
                logs::print("[Loader] fwpkclnt.sys found at 0x%p\n", resolve_module_base);
                module_resolved = true;
            } else {
                logs::print("[Loader] ERROR: fwpkclnt.sys not found - cannot resolve imports\n");
                return false;
            }
        }
        else if (str_compare_insensitive(module_name, "NDIS.SYS") == 0) {
            guest_module_info_t ndis_info = {};
            if (find_guest_module("NDIS.SYS", &ndis_info) && ndis_info.base_address) {
                resolve_module_base = ndis_info.base_address;
                logs::print("[Loader] NDIS.SYS found at 0x%p\n", resolve_module_base);
                module_resolved = true;
            } else {
                logs::print("[Loader] ERROR: NDIS.SYS not found - cannot resolve imports\n");
                return false;
            }
        }
        else {
            // Unknown module - try to find it dynamically
            guest_module_info_t unknown_info = {};
            if (find_guest_module(module_name, &unknown_info) && unknown_info.base_address) {
                resolve_module_base = unknown_info.base_address;
                logs::print("[Loader] %s found at 0x%p\n", module_name, resolve_module_base);
                module_resolved = true;
            } else {
                logs::print("[Loader] ERROR: Unknown module %s not found\n", module_name);
                return false;
            }
        }

        // 业务说明：定位 IAT 与 INT 并遍历导入函数。
        // 输入：import_descriptor；输出：first_thunk/original_first_thunk；规则：无原始表则用 IAT；异常：不抛出。
        auto first_thunk = reinterpret_cast<image_thunk_data64_t*>(
            image_base + import_descriptor->first_thunk
        );
        
        auto original_first_thunk = import_descriptor->original_first_thunk
            ? reinterpret_cast<image_thunk_data64_t*>(image_base + import_descriptor->original_first_thunk)
            : first_thunk;

        // 业务说明：解析导入函数并写入 IAT。
        // 输入：thunks；输出：IAT 更新；规则：不支持序号导入；异常：不抛出。
        while (original_first_thunk->u1.address_of_data) {
            // Check if import by ordinal (high bit set)
            if (original_first_thunk->u1.ordinal & (1ULL << 63)) {
                logs::print("[Loader] Error: Import by ordinal not supported\n");
                return false;
            }

            // Import by name
            const auto import_by_name = reinterpret_cast<image_import_by_name_t*>(
                image_base + original_first_thunk->u1.address_of_data
            );

            const char* func_name = import_by_name->name;
            
            // 业务说明：解析函数地址，必要时回退到 ntoskrnl。
            // 输入：resolve_module_base/func_name；输出：function_address；规则：解析失败返回错误；异常：不抛出。
            uint64_t function_address = get_kernel_export(resolve_module_base, func_name);

            // If not found and we're not already using ntoskrnl, try ntoskrnl as last resort
            // (only for re-exported functions like HAL)
            if (!function_address && resolve_module_base != ntoskrnl_base) {
                // Only try ntoskrnl fallback for HAL (which has many re-exports)
                if (str_compare_insensitive(module_name, "HAL.dll") == 0) {
                    function_address = get_kernel_export(ntoskrnl_base, func_name);
                    if (function_address) {
                        logs::print("[Loader] %s resolved via ntoskrnl re-export\n", func_name);
                    }
                }
            }

            if (!function_address) {
                // 业务说明：无法解析导入时终止加载。
                // 输入：module_name/func_name；输出：错误日志；规则：返回 false；异常：不抛出。
                logs::print("[Loader] ERROR: Failed to resolve import: %s!%s\n", 
                    module_name, func_name);
                return false;
            }

            // 业务说明：写入解析后的函数地址到 IAT。
            // 输入：function_address；输出：IAT 更新；规则：直接赋值；异常：不抛出。
            first_thunk->u1.function = function_address;
            functions_resolved++;

            // Move to next thunk
            first_thunk++;
            original_first_thunk++;
        }

        modules_resolved++;
        import_descriptor++;
    }

    logs::print("[Loader] Resolved %d functions from %d modules\n", 
        functions_resolved, modules_resolved);
    
    return true;
}

} // namespace loader
