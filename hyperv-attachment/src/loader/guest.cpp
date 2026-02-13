// =============================================================================
// VMM Shadow Mapper - Guest Kernel Discovery
// Provides utilities for locating kernel modules in Guest address space
// =============================================================================

#include "guest.h"
#include "pe.h"
#include "imports.h"
#include "../logs/logs.h"
#include "../crt/crt.h"
#include "../memory_manager/memory_manager.h"
#include "../arch/arch.h"
#include <intrin.h>

namespace loader {

// =============================================================================
// Internal State
// =============================================================================

namespace {
    cr3 g_guest_cr3 = {};
    cr3 g_slat_cr3 = {};
}

// =============================================================================
// Guest Context Management
// =============================================================================

/**
 * @description 设置来宾发现流程的 CR3。
 * @param {cr3} guest_cr3 来宾 CR3。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * set_discovery_cr3(cr3_value);
 */
void set_discovery_cr3(cr3 guest_cr3) {
    // 业务说明：缓存来宾 CR3 供后续内存读取使用。
    // 输入：guest_cr3；输出：g_guest_cr3 更新；规则：直接赋值；异常：不抛出。
    g_guest_cr3 = guest_cr3;
}

/**
 * @description 设置发现流程的 SLAT CR3。
 * @param {cr3} slat_cr3 SLAT CR3。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * set_discovery_slat_cr3(cr3_value);
 */
void set_discovery_slat_cr3(cr3 slat_cr3) {
    // 业务说明：缓存 SLAT CR3 供来宾内存读取使用。
    // 输入：slat_cr3；输出：g_slat_cr3 更新；规则：直接赋值；异常：不抛出。
    g_slat_cr3 = slat_cr3;
}

/**
 * @description 获取发现流程使用的来宾 CR3。
 * @param {void} 无。
 * @return {cr3} 来宾 CR3。
 * @throws {无} 不抛出异常。
 * @example
 * const auto cr3_value = get_discovery_cr3();
 */
cr3 get_discovery_cr3() {
    // 业务说明：返回当前缓存的来宾 CR3。
    // 输入：无；输出：g_guest_cr3；规则：直接返回；异常：不抛出。
    return g_guest_cr3;
}

/**
 * @description 获取发现流程使用的 SLAT CR3。
 * @param {void} 无。
 * @return {cr3} SLAT CR3。
 * @throws {无} 不抛出异常。
 * @example
 * const auto cr3_value = get_discovery_slat_cr3();
 */
cr3 get_discovery_slat_cr3() {
    // 业务说明：返回当前缓存的 SLAT CR3。
    // 输入：无；输出：g_slat_cr3；规则：直接返回；异常：不抛出。
    return g_slat_cr3;
}

// =============================================================================
// Memory Read Helper
// =============================================================================

/**
 * @description 读取来宾虚拟内存到缓冲区（显式 CR3）。
 * @param {uint64_t} guest_va 来宾虚拟地址。
 * @param {void*} buffer 输出缓冲区。
 * @param {uint64_t} size 读取大小。
 * @param {cr3} guest_cr3 来宾 CR3。
 * @param {cr3} slat_cr3 SLAT CR3。
 * @return {bool} 是否读取成功。
 * @throws {无} 不抛出异常。
 * @example
 * const auto ok = read_guest_memory_explicit(gva, buf, size, guest_cr3, slat_cr3);
 */
bool read_guest_memory_explicit(uint64_t guest_va, void* buffer, uint64_t size, cr3 guest_cr3, cr3 slat_cr3)
{
    // 业务说明：校验 CR3 并通过内存管理器读取来宾内存。
    // 输入：guest_va/buffer/size/guest_cr3/slat_cr3；输出：读取结果；规则：读满才成功；异常：不抛出。
    if (slat_cr3.flags == 0 || guest_cr3.flags == 0) {
        return false;
    }

    const uint64_t bytes_read = memory_manager::operate_on_guest_virtual_memory(
        slat_cr3,
        buffer,
        guest_va,
        guest_cr3,
        size,
        memory_operation_t::read_operation
    );

    return bytes_read == size;
}

/**
 * @description 读取来宾虚拟内存（使用缓存 CR3）。
 * @param {uint64_t} guest_va 来宾虚拟地址。
 * @param {void*} buffer 输出缓冲区。
 * @param {uint64_t} size 读取大小。
 * @return {bool} 是否读取成功。
 * @throws {无} 不抛出异常。
 * @example
 * const auto ok = read_guest_memory(gva, buf, size);
 */
static bool read_guest_memory(uint64_t guest_va, void* buffer, uint64_t size)
{
    // 业务说明：使用缓存的 CR3 读取来宾内存。
    // 输入：guest_va/buffer/size；输出：读取结果；规则：内部调用显式读取；异常：不抛出。
    return read_guest_memory_explicit(guest_va, buffer, size, g_guest_cr3, g_slat_cr3);
}



// =============================================================================
// PsLoadedModuleList Access
// =============================================================================

// KLDR_DATA_TABLE_ENTRY (simplified, 64-bit)
#pragma pack(push, 1)
struct ldr_data_table_entry_t {
    uint64_t in_load_order_links_flink;     // LIST_ENTRY.Flink
    uint64_t in_load_order_links_blink;     // LIST_ENTRY.Blink
    uint64_t exception_table;
    uint64_t exception_table_size;
    uint64_t gp_value;
    uint64_t non_paged_debug_info;
    uint64_t dll_base;                       // Module base address
    uint64_t entry_point;
    uint32_t size_of_image;                  // Size of module
    uint32_t padding1;
    // UNICODE_STRING FullDllName
    uint16_t full_dll_name_length;
    uint16_t full_dll_name_max_length;
    uint32_t padding2;
    uint64_t full_dll_name_buffer;
    // UNICODE_STRING BaseDllName
    uint16_t base_dll_name_length;
    uint16_t base_dll_name_max_length;
    uint32_t padding3;
    uint64_t base_dll_name_buffer;
    // ... more fields follow
};
#pragma pack(pop)

/**
 * @description 获取 PsLoadedModuleList 在来宾内核中的地址。
 * @param {uint64_t} ntoskrnl_base ntoskrnl 基址。
 * @return {uint64_t} PsLoadedModuleList 地址，失败返回 0。
 * @throws {无} 不抛出异常。
 * @example
 * const auto list = get_ps_loaded_module_list(nt_base);
 */
uint64_t get_ps_loaded_module_list(uint64_t ntoskrnl_base)
{
    // 业务说明：通过导出表解析 PsLoadedModuleList。
    // 输入：ntoskrnl_base；输出：导出地址；规则：base 为空返回 0；异常：不抛出。
    if (!ntoskrnl_base) {
        return 0;
    }

    // Find PsLoadedModuleList export
    return get_kernel_export(ntoskrnl_base, "PsLoadedModuleList");
}

// =============================================================================
// Module Enumeration
// =============================================================================

/**
 * @description 将来宾内存中的宽字符转换为 ASCII。
 * @param {uint64_t} wchar_buffer 宽字符缓冲区地址。
 * @param {uint16_t} length 字符串字节长度。
 * @param {char*} out_ascii 输出 ASCII 缓冲区。
 * @param {uint32_t} out_size 输出缓冲区大小。
 * @return {bool} 是否转换成功。
 * @throws {无} 不抛出异常。
 * @example
 * const auto ok = wchar_to_ascii(wchar_addr, len, buf, buf_size);
 */
static bool wchar_to_ascii(uint64_t wchar_buffer, uint16_t length, char* out_ascii, uint32_t out_size)
{
    // 业务说明：按字符读取来宾宽字符并截断为 ASCII。
    // 输入：wchar_buffer/length/out_ascii/out_size；输出：ASCII 字符串；规则：读失败填 '?'；异常：不抛出。
    if (!wchar_buffer || length == 0 || !out_ascii || out_size == 0) {
        return false;
    }

    // Read wide characters (2 bytes each)
    const uint32_t char_count = length / 2;
    const uint32_t copy_count = (char_count < out_size - 1) ? char_count : out_size - 1;

    for (uint32_t i = 0; i < copy_count; i++) {
        uint16_t wchar = 0;
        if (!read_guest_memory(wchar_buffer + i * 2, &wchar, sizeof(wchar))) {
            out_ascii[i] = '?';
        } else {
            out_ascii[i] = static_cast<char>(wchar & 0xFF);
        }
    }
    out_ascii[copy_count] = '\0';

    return true;
}

/**
 * @description 遍历来宾已加载模块并执行回调。
 * @param {bool (*)(const guest_module_info_t*, void*)} callback 回调函数。
 * @param {void*} context 回调上下文。
 * @return {uint32_t} 遍历到的模块数量。
 * @throws {无} 不抛出异常。
 * @example
 * const auto count = enumerate_guest_modules(cb, ctx);
 */
uint32_t enumerate_guest_modules(bool (*callback)(const guest_module_info_t* info, void* context), void* context)
{
    // 业务说明：遍历 PsLoadedModuleList 并构造模块信息。
    // 输入：callback/context；输出：模块数量；规则：最多 256 个；异常：不抛出。
    if (!g_module_cache.ntoskrnl_base) {
        logs::print("[Guest] Cannot enumerate: ntoskrnl not found\n");
        return 0;
    }

    const uint64_t ps_loaded_list = get_ps_loaded_module_list(g_module_cache.ntoskrnl_base);
    if (!ps_loaded_list) {
        logs::print("[Guest] PsLoadedModuleList not found\n");
        return 0;
    }

    // Read list head (Flink)
    uint64_t list_head_flink = 0;
    if (!read_guest_memory(ps_loaded_list, &list_head_flink, sizeof(list_head_flink))) {
        logs::print("[Guest] Failed to read PsLoadedModuleList\n");
        return 0;
    }

    uint32_t module_count = 0;
    uint64_t current = list_head_flink;

    // Walk the doubly-linked list
    while (current != ps_loaded_list && module_count < 256) {
        ldr_data_table_entry_t entry = {};
        
        if (!read_guest_memory(current, &entry, sizeof(entry))) {
            break;
        }

        guest_module_info_t info = {};
        info.base_address = entry.dll_base;
        info.size_of_image = entry.size_of_image;

        // Read module name
        wchar_to_ascii(entry.base_dll_name_buffer, entry.base_dll_name_length, 
                      info.name, sizeof(info.name));

        if (callback && !callback(&info, context)) {
            break;
        }

        module_count++;
        current = entry.in_load_order_links_flink;
    }

    return module_count;
}

// =============================================================================
// Module Discovery
// =============================================================================

struct find_module_ctx_t {
    const char* search_name;
    guest_module_info_t* result;
    bool found;
};

/**
 * @description 模块查找回调，匹配名称后返回结果。
 * @param {const guest_module_info_t*} info 模块信息。
 * @param {void*} context 查找上下文。
 * @return {bool} 是否继续遍历。
 * @throws {无} 不抛出异常。
 * @example
 * const auto cont = find_module_callback(info, &ctx);
 */
static bool find_module_callback(const guest_module_info_t* info, void* context)
{
    // 业务说明：比较模块名称并在匹配时终止遍历。
    // 输入：info/context；输出：是否继续；规则：匹配即返回 false；异常：不抛出。
    auto* ctx = static_cast<find_module_ctx_t*>(context);

    if (str_compare_insensitive(info->name, ctx->search_name) == 0) {
        *ctx->result = *info;
        ctx->found = true;
        return false;  // Stop enumeration
    }

    return true;  // Continue
}

/**
 * @description 在来宾模块列表中查找指定模块。
 * @param {const char*} module_name 模块名称。
 * @param {guest_module_info_t*} out_info 输出模块信息。
 * @return {bool} 是否找到。
 * @throws {无} 不抛出异常。
 * @example
 * const auto ok = find_guest_module("ntoskrnl.exe", &info);
 */
bool find_guest_module(const char* module_name, guest_module_info_t* out_info)
{
    // 业务说明：先查缓存，再遍历 PsLoadedModuleList。
    // 输入：module_name/out_info；输出：模块信息；规则：命中缓存直接返回；异常：不抛出。
    if (!module_name || !out_info) {
        return false;
    }

    // Check cache first
    const uint64_t cached = get_cached_module_base(module_name);
    if (cached) {
        out_info->base_address = cached;
        out_info->size_of_image = 0;  // Unknown from cache
        // Copy name
        for (int i = 0; i < 63 && module_name[i]; i++) {
            out_info->name[i] = module_name[i];
            out_info->name[i + 1] = '\0';
        }
        return true;
    }

    // Search via PsLoadedModuleList
    find_module_ctx_t ctx = {
        .search_name = module_name,
        .result = out_info,
        .found = false
    };

    enumerate_guest_modules(find_module_callback, &ctx);

    // Update cache if found
    if (ctx.found) {
        if (str_compare_insensitive(module_name, "NETIO.SYS") == 0) {
            g_module_cache.netio_base = out_info->base_address;
        }
        else if (str_compare_insensitive(module_name, "HAL.dll") == 0) {
            g_module_cache.hal_base = out_info->base_address;
        }
        else if (str_compare_insensitive(module_name, "fwpkclnt.sys") == 0) {
            g_module_cache.fwpkclnt_base = out_info->base_address;
        }
        else if (str_compare_insensitive(module_name, "NDIS.SYS") == 0) {
            g_module_cache.ndis_base = out_info->base_address;
        }
    }

    return ctx.found;
}

/**
 * @description 从缓存中获取模块基址。
 * @param {const char*} module_name 模块名称。
 * @return {uint64_t} 模块基址，未命中返回 0。
 * @throws {无} 不抛出异常。
 * @example
 * const auto base = get_cached_module_base("ntoskrnl.exe");
 */
uint64_t get_cached_module_base(const char* module_name)
{
    // 业务说明：按模块名称返回缓存中的基址。
    // 输入：module_name；输出：基址；规则：未命中返回 0；异常：不抛出。
    if (!module_name) return 0;

    if (str_compare_insensitive(module_name, "ntoskrnl.exe") == 0 ||
        str_compare_insensitive(module_name, "ntkrnlmp.exe") == 0) {
        return g_module_cache.ntoskrnl_base;
    }
    if (str_compare_insensitive(module_name, "HAL.dll") == 0) {
        return g_module_cache.hal_base;
    }
    if (str_compare_insensitive(module_name, "NETIO.SYS") == 0) {
        return g_module_cache.netio_base;
    }
    if (str_compare_insensitive(module_name, "fwpkclnt.sys") == 0) {
        return g_module_cache.fwpkclnt_base;
    }
    if (str_compare_insensitive(module_name, "NDIS.SYS") == 0) {
        return g_module_cache.ndis_base;
    }

    return 0;
}

// =============================================================================
// Initialization
// =============================================================================

/**
 * @description 初始化来宾模块发现流程。
 * @param {uint64_t} ntoskrnl_base ntoskrnl 基址。
 * @return {bool} 是否初始化成功。
 * @throws {无} 不抛出异常。
 * @example
 * const auto ok = init_guest_discovery(nt_base);
 */
bool init_guest_discovery(uint64_t ntoskrnl_base)
{
    // 业务说明：设置 ntoskrnl 基址并标记缓存初始化。
    // 输入：ntoskrnl_base；输出：初始化状态；规则：需要显式基址；异常：不抛出。
    if (g_module_cache.initialized) {
        return true;
    }

    // Set ntoskrnl base
    if (ntoskrnl_base) {
        g_module_cache.ntoskrnl_base = ntoskrnl_base;
    } else {
        // [ERROR] Auto-detect via MSR_LSTAR requires guest context now.
        // This function should be called from VMExit handler with explicit values.
        logs::print("[Guest] init_guest_discovery: Manual ntoskrnl base required\n");
        return false;
    }

    if (!g_module_cache.ntoskrnl_base) {
        logs::print("[Guest] Failed to initialize: ntoskrnl not found\n");
        return false;
    }

    logs::print("[Guest] Discovery initialized. ntoskrnl = 0x%p\n", g_module_cache.ntoskrnl_base);
    g_module_cache.initialized = 1;

    return true;
}

} // namespace loader
