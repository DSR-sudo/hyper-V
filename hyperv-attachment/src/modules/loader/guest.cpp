// =============================================================================
// VMM Shadow Mapper - Guest Kernel Discovery
// Provides utilities for locating kernel modules in Guest address space
// =============================================================================

#include "loader.h"
#include "pe.h"
#include "imports.h"
#include "../logs/logs.h"
#include "../crt/crt.h"
#include "../memory_manager/memory_manager.h"
#include "../memory_manager/heap_manager.h"
#include "../arch/arch.h"
#include <intrin.h>
#include <payload/payload_bin.h>

namespace loader {

/**
 * @description 验证 PE 格式的有效载荷数据。
 * @param {const unsigned char*} data 有效载荷数据指针。
 * @param {const size_t} size 有效载荷数据大小。
 * @return {bool} 如果数据是有效的 PE 文件则返回 true，否则返回 false。
 * @throws {无} 不抛出异常。
 * @example
 * const bool valid = validate_payload(payload_data, payload_size);
 */
bool validate_payload(const unsigned char* data, const size_t size)
{
    // 业务说明：验证 PE 文件格式的有效性，包括 DOS 头、NT 头和可选头。
    // 输入：data/size；输出：验证结果；规则：检查 DOS 签名、NT 签名和 PE64 标志；异常：不抛出。
    if (!data || size < sizeof(image_dos_header_t)) {
        return false;
    }

    const auto dos = reinterpret_cast<const image_dos_header_t*>(data);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    if (static_cast<size_t>(dos->e_lfanew) + sizeof(image_nt_headers64_t) > size) {
        return false;
    }

    const auto nt = reinterpret_cast<const image_nt_headers64_t*>(data + dos->e_lfanew);
    if (nt->signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    if (nt->optional_header.magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return false;
    }

    return true;
}

/**
 * @description 检查 RWbase 有效载荷是否已准备就绪。
 * @return {bool} 如果有效载荷已准备就绪则返回 true，否则返回 false。
 * @throws {无} 不抛出异常。
 * @example
 * const bool ready = is_payload_ready();
 */
bool is_payload_ready()
{
    // 业务说明：验证内置的 RWbase 有效载荷数据是否有效。
    // 输入：无；输出：验证结果；规则：调用 validate_payload 检查内置数据；异常：不抛出。
    return validate_payload(payload::rwbase_image, payload::rwbase_image_size);
}

/**
 * @description 获取 PE 映像中指定节的信息。
 * @param {const unsigned char*} image PE 映像数据。
 * @param {size_t} image_size 映像数据大小。
 * @param {uint16_t} section_index 节索引。
 * @param {section_info_t*} out_info 输出节信息结构体。
 * @return {bool} 如果成功获取节信息则返回 true，否则返回 false。
 * @throws {无} 不抛出异常。
 * @example
 * section_info_t info = {};
 * const bool success = get_payload_section_info(image_data, image_size, 0, &info);
 */
bool get_payload_section_info(const unsigned char* image, size_t image_size, uint16_t section_index, section_info_t* out_info)
{
    // 业务说明：解析 PE 文件结构，提取指定节的虚拟地址、大小和特性。
    // 输入：image/image_size/section_index/out_info；输出：节信息；规则：验证 PE 格式和索引范围；异常：不抛出。
    if (!image || !out_info || image_size < sizeof(image_dos_header_t)) {
        return false;
    }

    const auto dos = reinterpret_cast<const image_dos_header_t*>(image);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    if (dos->e_lfanew <= 0 || static_cast<size_t>(dos->e_lfanew) + sizeof(image_nt_headers64_t) > image_size) {
        return false;
    }

    const auto nt = reinterpret_cast<const image_nt_headers64_t*>(image + dos->e_lfanew);
    if (nt->signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    const uint64_t headers_base = reinterpret_cast<uint64_t>(&nt->optional_header);
    const uint64_t sections_base = headers_base + nt->file_header.size_of_optional_header;
    const uint64_t image_base = reinterpret_cast<uint64_t>(image);
    const uint64_t sections_offset = sections_base - image_base;
    const uint64_t sections_size = static_cast<uint64_t>(nt->file_header.number_of_sections) * sizeof(image_section_header_t);
    if (sections_offset + sections_size > image_size) {
        return false;
    }

    if (section_index >= nt->file_header.number_of_sections) {
        return false;
    }

    const auto sections = reinterpret_cast<const image_section_header_t*>(sections_base);
    const auto& section = sections[section_index];
    
    crt::copy_memory(out_info->name, section.name, 8);
    out_info->name[8] = '\0';
    
    out_info->virtual_address = section.virtual_address;
    out_info->virtual_size = section.virtual_size;
    out_info->raw_size = section.size_of_raw_data;
    out_info->characteristics = section.characteristics;
    return true;
}

/**
 * @description 为有效载荷部署分配临时缓冲区。
 * @param {context_t*} ctx 加载器上下文。
 * @param {const uint32_t} size 需要分配的缓冲区大小。
 * @param {allocation_info_t*} out_info 输出分配信息结构体。
 * @return {bool} 如果成功分配缓冲区则返回 true，否则返回 false。
 * @throws {无} 不抛出异常。
 * @example
 * allocation_info_t alloc = {};
 * const bool success = allocate_payload_staging_buffer(ctx, 0x10000, &alloc);
 */
bool allocate_payload_staging_buffer(context_t* ctx, const uint32_t size, allocation_info_t* out_info)
{
    // 业务说明：为有效载荷部署分配连续的物理页面作为临时缓冲区。
    // 输入：ctx/size/out_info；输出：分配信息；规则：按页对齐分配，确保连续性；异常：不抛出。
    if (!out_info || !ctx) {
        return false;
    }

    const uint32_t pages_needed = (size + 0xFFF) / 0x1000;

    logs::print(ctx->log_ctx, "[Loader] Allocating %d pages (%d bytes) for staging...\n",
        pages_needed, size);

    void* vmm_base = heap_manager::allocate_page(ctx->heap_ctx);
    if (!vmm_base) {
        logs::print(ctx->log_ctx, "[Loader] Failed to allocate initial page\n");
        return false;
    }

    for (uint32_t i = 1; i < pages_needed; i++) {
        void* page = heap_manager::allocate_page(ctx->heap_ctx);
        if (!page) {
            logs::print(ctx->log_ctx, "[Loader] Failed to allocate page %d of %d\n", i + 1, pages_needed);
            return false;
        }
        if (reinterpret_cast<uint8_t*>(page) !=
            reinterpret_cast<uint8_t*>(vmm_base) + (i * 0x1000)) {
            logs::print(ctx->log_ctx, "[Loader] ERROR: Non-contiguous allocation\n");
            return false;
        }
    }

    out_info->host_buffer = vmm_base;
    out_info->size = size;
    out_info->page_count = pages_needed;

    return true;
}

/**
 * @description 释放有效载荷部署的临时缓冲区。
 * @param {context_t*} ctx 加载器上下文。
 * @param {const allocation_info_t*} alloc 分配信息结构体。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * free_payload_staging_buffer(ctx, &alloc_info);
 */
void free_payload_staging_buffer(context_t* ctx, const allocation_info_t* alloc)
{
    // 业务说明：释放之前分配的临时缓冲区页面。
    // 输入：ctx/alloc；输出：无；规则：按页逐个释放；异常：不抛出。
    if (!ctx || !alloc || !alloc->host_buffer || alloc->page_count == 0) {
        return;
    }

    for (uint32_t i = 0; i < alloc->page_count; i++) {
        void* page = reinterpret_cast<uint8_t*>(alloc->host_buffer) + (static_cast<uint64_t>(i) * 0x1000);
        heap_manager::free_page(ctx->heap_ctx, page);
    }
}

/**
 * @description 将 PE 映像的节映射到目标缓冲区。
 * @param {void*} dest 目标缓冲区地址。
 * @param {const unsigned char*} src 源 PE 映像数据。
 * @param {const size_t} src_size 源映像数据大小。
 * @return {bool} 如果成功映射所有节则返回 true，否则返回 false。
 * @throws {无} 不抛出异常。
 * @example
 * const bool success = map_sections(buffer, image_data, image_size);
 */
bool map_sections(void* dest, const unsigned char* src, const size_t src_size)
{
    // 业务说明：将 PE 文件的节数据复制到目标缓冲区，包括头部和所有节数据。
    // 输入：dest/src/src_size；输出：映射结果；规则：复制头部，按节复制数据，填充虚拟大小；异常：不抛出。
    const auto dos = reinterpret_cast<const image_dos_header_t*>(src);
    const auto nt = reinterpret_cast<const image_nt_headers64_t*>(src + dos->e_lfanew);

    const uint32_t headers_size = nt->optional_header.size_of_headers;
    crt::copy_memory(dest, src, headers_size);

    const auto sections = reinterpret_cast<const image_section_header_t*>(
        reinterpret_cast<const uint8_t*>(&nt->optional_header) +
        nt->file_header.size_of_optional_header
    );

    for (uint16_t i = 0; i < nt->file_header.number_of_sections; i++) {
        const auto& section = sections[i];

        if (section.size_of_raw_data == 0) {
            continue;
        }

        if (section.pointer_to_raw_data + section.size_of_raw_data > src_size) {
            return false;
        }

        void* dest_section = reinterpret_cast<uint8_t*>(dest) + section.virtual_address;
        const void* src_section = src + section.pointer_to_raw_data;

        crt::copy_memory(dest_section, src_section, section.size_of_raw_data);

        if (section.virtual_size > section.size_of_raw_data) {
            const uint32_t padding = section.virtual_size - section.size_of_raw_data;
            crt::set_memory(
                reinterpret_cast<uint8_t*>(dest_section) + section.size_of_raw_data,
                0,
                padding
            );
        }
    }

    return true;
}

/**
 * @description 根据 PE 节特性设置来宾内存页面的权限。
 * @param {context_t*} ctx 加载器上下文。
 * @param {uint64_t} target_va 目标虚拟地址（PE 映像基址）。
 * @param {const unsigned char*} image PE 映像数据。
 * @param {size_t} image_size 映像数据大小。
 * @return {bool} 如果成功设置所有节权限则返回 true，否则返回 false。
 * @throws {无} 不抛出异常。
 * @example
 * const bool success = apply_section_permissions(ctx, base_address, image_data, image_size);
 */
bool apply_section_permissions(context_t* ctx, uint64_t target_va, const unsigned char* image, size_t image_size)
{
    // 业务说明：根据 PE 节的特性（读/写/执行）设置来宾内存页面的 EPT 权限。
    // 输入：ctx/target_va/image/image_size；输出：权限设置结果；规则：按节解析特性并设置权限；异常：不抛出。
    if (!ctx || !image) {
        return false;
    }

    const auto dos = reinterpret_cast<const image_dos_header_t*>(image);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }
    if (dos->e_lfanew <= 0 || static_cast<size_t>(dos->e_lfanew) + sizeof(image_nt_headers64_t) > image_size) {
        return false;
    }
    const auto nt = reinterpret_cast<const image_nt_headers64_t*>(image + dos->e_lfanew);
    if (nt->signature != IMAGE_NT_SIGNATURE) {
        return false;
    }
    const uint16_t section_count = nt->file_header.number_of_sections;

    for (uint16_t i = 0; i < section_count; ++i) {
        section_info_t info = {};
        if (!get_payload_section_info(image, image_size, i, &info)) {
            return false;
        }

        uint32_t section_size = info.virtual_size;
        if (section_size == 0) {
            section_size = info.raw_size;
        }
        if (section_size == 0) {
            continue;
        }

        const uint64_t section_va = target_va + static_cast<uint64_t>(info.virtual_address);
        const bool allow_read = (info.characteristics & 0x40000000u) != 0;
        const bool allow_write = (info.characteristics & 0x80000000u) != 0;
        const bool allow_execute = (info.characteristics & 0x20000000u) != 0;

        logs::print(ctx->log_ctx, "[Injection] Stage 3: Section VA=0x%p Size=0x%X R=%d W=%d X=%d\n",
            section_va, section_size, allow_read, allow_write, allow_execute);

        if (!memory_manager::set_guest_page_permissions(ctx->guest_cr3, ctx->slat_cr3, section_va, 0, section_size, allow_read, allow_write, allow_execute)) {
            return false;
        }
    }

    return true;
}

/**
 * @description 清除 PE 映像头部数据以增加隐蔽性。
 * @param {context_t*} ctx 加载器上下文。
 * @param {uint64_t} target_va 目标虚拟地址（PE 映像基址）。
 * @param {const unsigned char*} image PE 映像数据。
 * @param {size_t} image_size 映像数据大小。
 * @return {bool} 如果成功清除头部数据则返回 true，否则返回 false。
 * @throws {无} 不抛出异常。
 * @example
 * const bool success = wipe_pe_headers(ctx, base_address, image_data, image_size);
 */
bool wipe_pe_headers(context_t* ctx, uint64_t target_va, const unsigned char* image, size_t image_size)
{
    // 业务说明：将 PE 映像头部数据清零，防止被检测工具识别。
    // 输入：ctx/target_va/image/image_size；输出：清除结果；规则：先设置 RW 权限，清零数据，再设置 R 权限；异常：不抛出。
    if (!ctx || !image) {
        return false;
    }

    const auto dos = reinterpret_cast<const image_dos_header_t*>(image);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }
    if (dos->e_lfanew <= 0 || static_cast<size_t>(dos->e_lfanew) + sizeof(image_nt_headers64_t) > image_size) {
        return false;
    }
    const auto nt = reinterpret_cast<const image_nt_headers64_t*>(image + dos->e_lfanew);
    if (nt->signature != IMAGE_NT_SIGNATURE) {
        return false;
    }
    const uint32_t headers_size = nt->optional_header.size_of_headers;
    if (headers_size == 0 || headers_size > image_size) {
        return false;
    }

    if (!memory_manager::set_guest_page_permissions(ctx->guest_cr3, ctx->slat_cr3, target_va, 0, headers_size, true, true, false)) {
        return false;
    }

    uint8_t zero_page[0x100] = {};
    uint32_t remaining = headers_size;
    uint64_t current_va = target_va;
    while (remaining > 0) {
        const uint32_t chunk = remaining > sizeof(zero_page) ? static_cast<uint32_t>(sizeof(zero_page)) : remaining;
        const uint64_t bytes_written = memory_manager::operate_on_guest_virtual_memory(
            ctx->slat_cr3,
            zero_page,
            current_va,
            ctx->guest_cr3,
            chunk,
            memory_operation_t::write_operation
        );
        if (bytes_written != chunk) {
            return false;
        }
        current_va += chunk;
        remaining -= chunk;
    }

    if (!memory_manager::set_guest_page_permissions(ctx->guest_cr3, ctx->slat_cr3, target_va, 0, headers_size, true, false, false)) {
        return false;
    }

    return true;
}

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
