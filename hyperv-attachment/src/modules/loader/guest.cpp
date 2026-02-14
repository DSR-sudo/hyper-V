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
    // 业务说明：私有变量已移除，转而使用 context_t 传递状态。
}

// =============================================================================
// Guest Context Management
// =============================================================================

/**
 * @description 设置来宾发现流程的 CR3。
 * @param {context_t*} ctx 加载器上下文。
 * @param {cr3} guest_cr3 来宾 CR3。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * set_discovery_cr3(ctx, cr3_value);
 */
void set_discovery_cr3(context_t* ctx, cr3 guest_cr3) {
    // 业务说明：缓存来宾 CR3 供后续内存读取使用。
    // 输入：ctx/guest_cr3；输出：ctx->guest_cr3 更新；规则：直接赋值；异常：不抛出。
    ctx->guest_cr3 = guest_cr3;
}

/**
 * @description 设置发现流程的 SLAT CR3。
 * @param {context_t*} ctx 加载器上下文。
 * @param {cr3} slat_cr3 SLAT CR3。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * set_discovery_slat_cr3(ctx, cr3_value);
 */
void set_discovery_slat_cr3(context_t* ctx, cr3 slat_cr3) {
    // 业务说明：缓存 SLAT CR3 供来宾内存读取使用。
    // 输入：ctx/slat_cr3；输出：ctx->slat_cr3 更新；规则：直接赋值；异常：不抛出。
    ctx->slat_cr3 = slat_cr3;
}

/**
 * @description 获取发现流程使用的来宾 CR3。
 * @param {context_t*} ctx 加载器上下文。
 * @return {cr3} 来宾 CR3。
 * @throws {无} 不抛出异常。
 * @example
 * const auto cr3_value = get_discovery_cr3(ctx);
 */
cr3 get_discovery_cr3(context_t* ctx) {
    // 业务说明：返回当前缓存的来宾 CR3。
    // 输入：ctx；输出：ctx->guest_cr3；规则：直接返回；异常：不抛出。
    return ctx->guest_cr3;
}

/**
 * @description 获取发现流程使用的 SLAT CR3。
 * @param {context_t*} ctx 加载器上下文。
 * @return {cr3} SLAT CR3。
 * @throws {无} 不抛出异常。
 * @example
 * const auto cr3_value = get_discovery_slat_cr3(ctx);
 */
cr3 get_discovery_slat_cr3(context_t* ctx) {
    // 业务说明：返回当前缓存的 SLAT CR3。
    // 输入：ctx；输出：ctx->slat_cr3；规则：直接返回；异常：不抛出。
    return ctx->slat_cr3;
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
 * @param {context_t*} ctx 加载器上下文。
 * @param {uint64_t} guest_va 来宾虚拟地址。
 * @param {void*} buffer 输出缓冲区。
 * @param {uint64_t} size 读取大小。
 * @return {bool} 是否读取成功。
 * @throws {无} 不抛出异常。
 * @example
 * const auto ok = read_guest_memory(ctx, gva, buf, size);
 */
static bool read_guest_memory(context_t* ctx, uint64_t guest_va, void* buffer, uint64_t size)
{
    // 业务说明：使用缓存的 CR3 读取来宾内存。
    // 输入：ctx/guest_va/buffer/size；输出：读取结果；规则：内部调用显式读取；异常：不抛出。
    return read_guest_memory_explicit(guest_va, buffer, size, ctx->guest_cr3, ctx->slat_cr3);
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
 * @param {context_t*} ctx 加载器上下文。
 * @param {uint64_t} ntoskrnl_base ntoskrnl 基址。
 * @return {uint64_t} PsLoadedModuleList 地址，失败返回 0。
 * @throws {无} 不抛出异常。
 * @example
 * const auto list = get_ps_loaded_module_list(ctx, nt_base);
 */
uint64_t get_ps_loaded_module_list(context_t* ctx, uint64_t ntoskrnl_base)
{
    // 业务说明：通过导出表解析 PsLoadedModuleList。
    // 输入：ctx/ntoskrnl_base；输出：导出地址；规则：base 为空返回 0；异常：不抛出。
    if (!ntoskrnl_base) {
        return 0;
    }

    // Find PsLoadedModuleList export
    return get_kernel_export(ctx, ntoskrnl_base, "PsLoadedModuleList");
}

// =============================================================================
// Module Enumeration
// =============================================================================

/**
 * @description 将来宾内存中的宽字符转换为 ASCII。
 * @param {context_t*} ctx 加载器上下文。
 * @param {uint64_t} wchar_buffer 宽字符缓冲区地址。
 * @param {uint16_t} length 字符串字节长度。
 * @param {char*} out_ascii 输出 ASCII 缓冲区。
 * @param {uint32_t} out_size 输出缓冲区大小。
 * @return {bool} 是否转换成功。
 * @throws {无} 不抛出异常。
 * @example
 * const auto ok = wchar_to_ascii(ctx, wchar_addr, len, buf, buf_size);
 */
static bool wchar_to_ascii(context_t* ctx, uint64_t wchar_buffer, uint16_t length, char* out_ascii, uint32_t out_size)
{
    // 业务说明：按字符读取来宾宽字符并截断为 ASCII。
    // 输入：ctx/wchar_buffer/length/out_ascii/out_size；输出：ASCII 字符串；规则：读失败填 '?'；异常：不抛出。
    if (!wchar_buffer || length == 0 || !out_ascii || out_size == 0) {
        return false;
    }

    // Read wide characters (2 bytes each)
    const uint32_t char_count = length / 2;
    const uint32_t copy_count = (char_count < out_size - 1) ? char_count : out_size - 1;

    for (uint32_t i = 0; i < copy_count; i++) {
        uint16_t wchar = 0;
        if (!read_guest_memory(ctx, wchar_buffer + i * 2, &wchar, sizeof(wchar))) {
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
 * @param {context_t*} ctx 加载器上下文。
 * @param {bool (*)(const guest_module_info_t*, void*)} callback 回调函数。
 * @param {void*} context 回调上下文。
 * @return {uint32_t} 遍历到的模块数量。
 * @throws {无} 不抛出异常。
 * @example
 * const auto count = enumerate_guest_modules(ctx, cb, ctx_ptr);
 */
uint32_t enumerate_guest_modules(context_t* ctx, bool (*callback)(const guest_module_info_t* info, void* context), void* context)
{
    // 业务说明：遍历 PsLoadedModuleList 并构造模块信息。
    // 输入：ctx/callback/context；输出：模块数量；规则：最多 256 个；异常：不抛出。
    if (!ctx->module_cache.ntoskrnl_base) {
        logs::print(ctx->log_ctx, "[Guest] Cannot enumerate: ntoskrnl not found\n");
        return 0;
    }

    const uint64_t ps_loaded_list = get_ps_loaded_module_list(ctx, ctx->module_cache.ntoskrnl_base);
    if (!ps_loaded_list) {
        logs::print(ctx->log_ctx, "[Guest] PsLoadedModuleList not found\n");
        return 0;
    }

    // Read list head (Flink)
    uint64_t list_head_flink = 0;
    if (!read_guest_memory(ctx, ps_loaded_list, &list_head_flink, sizeof(list_head_flink))) {
        logs::print(ctx->log_ctx, "[Guest] Failed to read PsLoadedModuleList\n");
        return 0;
    }

    uint32_t module_count = 0;
    uint64_t current = list_head_flink;

    // Walk the doubly-linked list
    while (current != ps_loaded_list && module_count < 256) {
        ldr_data_table_entry_t entry = {};
        
        if (!read_guest_memory(ctx, current, &entry, sizeof(entry))) {
            break;
        }

        guest_module_info_t info = {};
        info.base_address = entry.dll_base;
        info.size_of_image = entry.size_of_image;

        // Read module name
        wchar_to_ascii(ctx, entry.base_dll_name_buffer, entry.base_dll_name_length, 
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
 * @param {context_t*} ctx 加载器上下文。
 * @param {const char*} module_name 模块名称。
 * @param {guest_module_info_t*} out_info 输出模块信息。
 * @return {bool} 是否找到。
 * @throws {无} 不抛出异常。
 * @example
 * const auto ok = find_guest_module(ctx, "ntoskrnl.exe", &info);
 */
bool find_guest_module(context_t* ctx, const char* module_name, guest_module_info_t* out_info)
{
    // 业务说明：先查缓存，再遍历 PsLoadedModuleList。
    // 输入：ctx/module_name/out_info；输出：模块信息；规则：命中缓存直接返回；异常：不抛出。
    if (!module_name || !out_info) {
        return false;
    }

    // Check cache first
    const uint64_t cached = get_cached_module_base(ctx, module_name);
    if (cached) {
        out_info->base_address = cached;
        out_info->size_of_image = 0;  // Unknown from cache
        crt::copy_memory(out_info->name, module_name, crt::string_length(module_name) + 1);
        return true;
    }

    find_module_ctx_t find_ctx = { module_name, out_info, false };
    enumerate_guest_modules(ctx, find_module_callback, &find_ctx);

    return find_ctx.found;
}

/**
 * @description 获取缓存的模块基址。
 * @param {context_t*} ctx 加载器上下文。
 * @param {const char*} module_name 模块名称。
 * @return {uint64_t} 缓存的基址，未找到返回 0。
 * @throws {无} 不抛出异常。
 * @example
 * const auto base = get_cached_module_base(ctx, "ntoskrnl.exe");
 */
uint64_t get_cached_module_base(context_t* ctx, const char* module_name)
{
    // 业务说明：根据名称从上下文缓存中检索基址。
    // 输入：ctx/module_name；输出：缓存基址；规则：不区分大小写；异常：不抛出。
    if (str_compare_insensitive(module_name, "ntoskrnl.exe") == 0) return ctx->module_cache.ntoskrnl_base;
    if (str_compare_insensitive(module_name, "hal.dll") == 0) return ctx->module_cache.hal_base;
    if (str_compare_insensitive(module_name, "NETIO.SYS") == 0) return ctx->module_cache.netio_base;
    if (str_compare_insensitive(module_name, "fwpkclnt.sys") == 0) return ctx->module_cache.fwpkclnt_base;
    if (str_compare_insensitive(module_name, "ndis.sys") == 0) return ctx->module_cache.ndis_base;

    return 0;
}

/**
 * @description 初始化来宾内核发现与缓存。
 * @param {context_t*} ctx 加载器上下文。
 * @param {uint64_t} ntoskrnl_base 已知的 ntoskrnl 基址（可选）。
 * @return {bool} 是否初始化成功。
 * @throws {无} 不抛出异常。
 * @example
 * const auto ok = init_guest_discovery(ctx, nt_base);
 */
bool init_guest_discovery(context_t* ctx, uint64_t ntoskrnl_base)
{
    // 业务说明：发现核心模块基址并填充缓存。
    // 输入：ctx/ntoskrnl_base；输出：缓存初始化；规则：必须先找到 ntoskrnl；异常：不抛出。
    if (ctx->module_cache.initialized) {
        return true;
    }

    // 1. Find ntoskrnl
    if (ntoskrnl_base) {
        ctx->module_cache.ntoskrnl_base = ntoskrnl_base;
        logs::print(ctx->log_ctx, "[Guest] Using provided ntoskrnl base\n");
    } else if (!ctx->module_cache.ntoskrnl_base) {
        logs::print(ctx->log_ctx, "[Guest] ntoskrnl base not provided\n");
        return false;
    }

    // 2. Find other core modules via PsLoadedModuleList
    guest_module_info_t info = {};
    if (find_guest_module(ctx, "hal.dll", &info)) ctx->module_cache.hal_base = info.base_address;
    if (find_guest_module(ctx, "NETIO.SYS", &info)) ctx->module_cache.netio_base = info.base_address;
    if (find_guest_module(ctx, "fwpkclnt.sys", &info)) ctx->module_cache.fwpkclnt_base = info.base_address;
    if (find_guest_module(ctx, "ndis.sys", &info)) ctx->module_cache.ndis_base = info.base_address;

    ctx->module_cache.initialized = 1;
    return true;
}

} // namespace loader
