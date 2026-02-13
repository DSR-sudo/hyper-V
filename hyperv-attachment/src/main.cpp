#include "memory_manager/memory_manager.h"
#include "memory_manager/heap_manager.h"
#include "logs/logs.h"
#include <ia32-doc/ia32.hpp>
#include <cstdint>

#include "crt/crt.h"
#include "slat/slat.h"
#include "runtime/vmexit_dispatch.h"

namespace
{
    std::uint64_t g_image_base = 0;
    std::uint64_t g_image_size = 0;
    std::uint64_t g_text_start = 0;
    std::uint64_t g_text_end = 0;
    std::uint64_t g_data_start = 0;
    std::uint64_t g_data_end = 0;
}

#pragma pack(push, 1)
struct image_dos_header {
    std::uint16_t e_magic;
    std::uint8_t  _pad[58];
    std::int32_t  e_lfanew;
};

struct image_file_header {
    std::uint16_t machine;
    std::uint16_t number_of_sections;
    std::uint32_t time_date_stamp;
    std::uint32_t pointer_to_symbol_table;
    std::uint32_t number_of_symbols;
    std::uint16_t size_of_optional_header;
    std::uint16_t characteristics;
};

struct image_data_directory {
    std::uint32_t virtual_address;
    std::uint32_t size;
};

struct image_optional_header64 {
    std::uint16_t magic;
    std::uint8_t  _pad1[66];
    std::uint64_t image_base;
    std::uint32_t section_alignment;
    std::uint32_t file_alignment;
    std::uint8_t  _pad2[46];
    std::uint32_t size_of_image;
    std::uint32_t size_of_headers;
    std::uint32_t check_sum;
    std::uint8_t  _pad3[10];
    std::uint32_t number_of_rva_and_sizes;
    image_data_directory data_directory[16];
};

struct image_nt_headers64 {
    std::uint32_t signature;
    image_file_header file_header;
    image_optional_header64 optional_header;
};

struct image_section_header {
    std::uint8_t  name[8];
    std::uint32_t virtual_size;
    std::uint32_t virtual_address;
    std::uint32_t size_of_raw_data;
    std::uint32_t pointer_to_raw_data;
    std::uint32_t pointer_to_relocations;
    std::uint32_t pointer_to_linenumbers;
    std::uint16_t number_of_relocations;
    std::uint16_t number_of_linenumbers;
    std::uint32_t characteristics;
};
#pragma pack(pop)

/**
 * @description 模块入口，初始化堆、日志与 SLAT，并解析自身 PE 边界。
 * @param {std::uint8_t** const} vmexit_handler_detour_out 输出 VMExit Detour 指针。
 * @param {std::uint8_t* const} original_vmexit_handler_routine 原 VMExit 处理器地址。
 * @param {const std::uint64_t} heap_physical_base 堆物理基址。
 * @param {const std::uint64_t} heap_physical_usable_base 堆可用物理基址。
 * @param {const std::uint64_t} heap_total_size 堆总大小。
 * @param {const std::uint64_t} _uefi_boot_physical_base_address UEFI Boot 镜像物理基址。
 * @param {const std::uint32_t} _uefi_boot_image_size UEFI Boot 镜像大小。
 * @param {const std::uint64_t} reserved_one 预留参数（Intel）。
 * @param {const std::uint64_t} ntoskrnl_base_from_uefi UEFI 传入的 ntoskrnl 基址。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * entry_point(&detour_out, original_handler, heap_base, heap_usable, heap_size, uefi_base, uefi_size, 0, nt_base);
 */
void entry_point(std::uint8_t** const vmexit_handler_detour_out, std::uint8_t* const original_vmexit_handler_routine, const std::uint64_t heap_physical_base, const std::uint64_t heap_physical_usable_base, const std::uint64_t heap_total_size, const std::uint64_t _uefi_boot_physical_base_address, const std::uint32_t _uefi_boot_image_size, const std::uint64_t reserved_one, const std::uint64_t ntoskrnl_base_from_uefi)
{
    (void)reserved_one; // Intel Only

    // Task 1.4: Receive ntoskrnl_base captured by uefi-boot from LoaderBlock
    if (ntoskrnl_base_from_uefi != 0)
    {
        // 业务说明：接收 UEFI 传入的 ntoskrnl 基址，供导出解析使用。
        // 输入：ntoskrnl_base_from_uefi；输出：ntoskrnl_base 缓存；规则：仅非零时更新；异常：不抛出。
        set_ntoskrnl_base(ntoskrnl_base_from_uefi);
    }

    // 业务说明：记录 VMExit 处理器与 UEFI 镜像参数，完成全局初始化。
    // 输入：入口参数；输出：VMExit 运行时状态；规则：仅入口阶段设置；异常：不抛出。
    set_vmexit_runtime_state(original_vmexit_handler_routine, _uefi_boot_physical_base_address, _uefi_boot_image_size);
    heap_manager::initial_physical_base = heap_physical_base;
    heap_manager::initial_size = heap_total_size;

    *vmexit_handler_detour_out = reinterpret_cast<std::uint8_t*>(vmexit_handler_detour);

    const std::uint64_t heap_physical_end = heap_physical_base + heap_total_size;
    const std::uint64_t heap_usable_size = heap_physical_end - heap_physical_usable_base;

    // 业务说明：映射堆物理内存并初始化堆管理。
    // 输入：堆物理基址与大小；输出：堆管理器可用；规则：映射成功后初始化；异常：不抛出。
    void* const mapped_heap_usable_base = memory_manager::map_host_physical(heap_physical_usable_base);
    heap_manager::set_up(mapped_heap_usable_base, heap_usable_size);

    // 业务说明：初始化日志系统，为后续阶段输出状态。
    // 输入：无；输出：日志系统可用；规则：入口阶段初始化；异常：不抛出。
    logs::set_up();

    // [ARCHITECT Phase 2] PE Parsing & Boundary Locking
    // 业务说明：解析自身 PE 头与节区边界，记录镜像与代码/数据范围。
    // 输入：映射后的镜像基址；输出：镜像与节区边界；规则：仅在签名合法时更新；异常：不抛出。
    const auto image_base = static_cast<std::uint8_t*>(memory_manager::map_host_physical(heap_physical_base));
    const auto dos_header = reinterpret_cast<image_dos_header*>(image_base);

    if (dos_header->e_magic == 0x5A4D)
    {
        const auto nt_headers = reinterpret_cast<image_nt_headers64*>(image_base + dos_header->e_lfanew);
        if (nt_headers->signature == 0x00004550)
        {
            // 业务说明：记录镜像基址与镜像大小，供后续内存隐藏与保护策略使用。
            // 输入：PE 头解析结果；输出：g_image_base/g_image_size；规则：仅在签名合法时更新；异常：不抛出。
            g_image_base = heap_physical_base;
            g_image_size = nt_headers->optional_header.size_of_image;
            
            auto section_header = reinterpret_cast<image_section_header*>(reinterpret_cast<std::uint8_t*>(&nt_headers->optional_header) + nt_headers->file_header.size_of_optional_header);

            logs::print("[Init] Hyper-reV Entry Point reached.\n");
            logs::print("[Init] Heap Physical Base: 0x%p, Size: 0x%p\n", heap_physical_base, heap_total_size);
            logs::print("[Init] UEFI Boot Physical Base: 0x%p, Size: 0x%x\n", _uefi_boot_physical_base_address, _uefi_boot_image_size);
            
            if (get_ntoskrnl_base() != 0)
            {
                logs::print("[Task 1.4] ntoskrnl_base received from UEFI: 0x%p\n", get_ntoskrnl_base());
            }
            else
            {
                logs::print("[Task 1.4] CRITICAL ERROR: ntoskrnl_base not received from UEFI. System may be unstable.\n");
            }
            
            logs::print("[Stealth] PE Image Base: 0x%p\n", g_image_base);
            logs::print("[Stealth] Full Image Range: 0x%p - 0x%p\n", g_image_base, g_image_base + g_image_size);

            for (std::uint32_t i = 0; i < nt_headers->file_header.number_of_sections; i++)
            {
                // 业务说明：遍历节区记录范围，定位 .text/.data 边界。
                // 输入：节区表；输出：g_text_start/g_text_end/g_data_start/g_data_end；规则：名称匹配才更新；异常：不抛出。
                const auto& section = section_header[i];
                char section_name[9] = { 0 };
                crt::copy_memory(section_name, section.name, 8);

                logs::print("[Stealth] Section [%s]: 0x%p - 0x%p\n", 
                    section_name, 
                    heap_physical_base + section.virtual_address, 
                    heap_physical_base + section.virtual_address + section.virtual_size);

                if (crt::abs(static_cast<std::int32_t>(section.name[0] - '.')) == 0 && 
                    crt::abs(static_cast<std::int32_t>(section.name[1] - 't')) == 0 && 
                    crt::abs(static_cast<std::int32_t>(section.name[2] - 'e')) == 0 && 
                    crt::abs(static_cast<std::int32_t>(section.name[3] - 'x')) == 0 && 
                    crt::abs(static_cast<std::int32_t>(section.name[4] - 't')) == 0)
                {
                    // 业务说明：识别 .text 节并记录其物理范围。
                    // 输入：section；输出：g_text_start/g_text_end；规则：名称匹配 .text；异常：不抛出。
                    g_text_start = heap_physical_base + section.virtual_address;
                    g_text_end = g_text_start + section.virtual_size;
                }
                else if (crt::abs(static_cast<std::int32_t>(section.name[0] - '.')) == 0 && 
                         crt::abs(static_cast<std::int32_t>(section.name[1] - 'd')) == 0 && 
                         crt::abs(static_cast<std::int32_t>(section.name[2] - 'a')) == 0 && 
                         crt::abs(static_cast<std::int32_t>(section.name[3] - 't')) == 0 && 
                         crt::abs(static_cast<std::int32_t>(section.name[4] - 'a')) == 0)
                {
                    // 业务说明：识别 .data 节并记录其物理范围。
                    // 输入：section；输出：g_data_start/g_data_end；规则：名称匹配 .data；异常：不抛出。
                    g_data_start = heap_physical_base + section.virtual_address;
                    g_data_end = g_data_start + section.virtual_size;
                }
            }
        }
    }
    else
    {
        logs::print("[WARNING] PE Parsing failed! Image base not found.\n");
    }

    // 业务说明：初始化 SLAT 子系统，完成内存虚拟化准备。
    // 输入：无；输出：SLAT 可用；规则：入口阶段初始化；异常：不抛出。
    slat::set_up();
    logs::print("[Init] Component setup complete (Logs, SLAT).\n");
}
