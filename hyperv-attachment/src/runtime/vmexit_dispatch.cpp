#include "vmexit_dispatch.h"

#include "../arch/arch.h"
#include "../crt/crt.h"
#include "../hypercall/hypercall.h"
#include <hypercall/hypercall_def.h>
#include "../interrupts/interrupts.h"
#include "../loader/imports.h"
#include "../logs/logs.h"
#include "../memory_manager/memory_manager.h"
#include "../slat/slat.h"
#include "../slat/cr3/cr3.h"
#include "../slat/violation/violation.h"
#include <structures/trap_frame.h>

namespace
{
    std::uint8_t* original_vmexit_handler = nullptr;
    std::uint64_t uefi_boot_physical_base_address = 0;
    std::uint64_t uefi_boot_image_size = 0;
    std::uint64_t ntoskrnl_base = 0;
}

/**
 * @description 判断是否为合法的 Hypercall 请求。
 * @param {const hypercall_info_t&} hypercall_info Hypercall 关键信息，包含主次校验键。
 * @return {bool} 是否匹配 Hypercall 主次校验键。
 * @throws {无} 不抛出异常。
 * @example
 * const hypercall_info_t info = { .value = trap_frame->rcx };
 * const bool is_valid = is_hypercall_request(info);
 */
bool is_hypercall_request(const hypercall_info_t& hypercall_info)
{
    return hypercall_info.primary_key == hypercall_primary_key && hypercall_info.secondary_key == hypercall_secondary_key;
}

/**
 * @description 尝试处理 Hypercall VMExit 请求。
 * @param {const std::uint64_t} a1 VMExit 上下文参数。
 * @return {bool} 是否为 Hypercall 并已处理。
 * @throws {无} 不抛出异常。
 * @example
 * const bool handled = try_process_hypercall_exit(a1);
 */
bool try_process_hypercall_exit(const std::uint64_t a1)
{
    // 业务说明：从 TrapFrame 提取 Hypercall 信息并校验密钥。
    // 输入：VMExit TrapFrame 指针；输出：是否处理；规则：密钥匹配才处理；异常：不抛出。
    trap_frame_t* const trap_frame = *reinterpret_cast<trap_frame_t**>(a1);
    const hypercall_info_t hypercall_info = { .value = trap_frame->rcx };

    if (!is_hypercall_request(hypercall_info))
    {
        return false;
    }

    // 业务说明：保存与恢复来宾栈指针，执行 Hypercall 处理并推进来宾 RIP。
    // 输入：trap_frame 与 hypercall_info；输出：处理结果；规则：执行后推进 RIP；异常：不抛出。
    trap_frame->rsp = arch::get_guest_rsp();
    hypercall::process(hypercall_info, trap_frame);
    arch::set_guest_rsp(trap_frame->rsp);
    arch::advance_guest_rip();
    return true;
}

/**
 * @description VMExit 分发处理，按退出类型路由到对应模块。
 * @param {const std::uint64_t} exit_reason VMExit 退出原因。
 * @param {const std::uint64_t} a1 VMExit 上下文参数，用于处理 CPUID/HYPERCALL。
 * @return {bool} 是否已被当前分发处理并可提前返回。
 * @throws {无} 不抛出异常。
 * @example
 * const bool handled = dispatch_vmexit(exit_reason, a1);
 */
bool dispatch_vmexit(const std::uint64_t exit_reason, const std::uint64_t a1)
{
    // 业务说明：根据 VMExit 原因选择处理路径，确保 Hypercall 与 SLAT/NMI/MTF 各自独立。
    // 输入：exit_reason 与 VMExit 上下文参数；输出：是否已处理；规则：CPUID 仅处理符合密钥的 Hypercall；异常：不抛出。
    if (arch::is_cpuid(exit_reason) == 1)
    {
        return try_process_hypercall_exit(a1);
    }

    if (arch::is_slat_violation(exit_reason) == 1 && slat::violation::process() == 1)
    {
        return true;
    }

    if (arch::is_non_maskable_interrupt_exit(exit_reason) == 1)
    {
        interrupts::process_nmi();
        return false;
    }

    if (arch::is_mtf_exit(exit_reason) == 1)
    {
        slat::violation::handle_mtf();
        return true;
    }

    return false;
}

/**
 * @description 清理 UEFI 启动镜像，抹除其物理内存内容。
 * @param {void} 无。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * clean_up_uefi_boot_image();
 */
void clean_up_uefi_boot_image()
{
    // 业务说明：通过 Host 物理映射清理 UEFI 启动镜像内容，降低残留痕迹。
    // 输入：uefi_boot_physical_base_address 与 uefi_boot_image_size；输出：清零后的物理内存；规则：仅在有效映射后写零；异常：不抛出。
    const auto mapped_uefi_boot_base = static_cast<std::uint8_t*>(memory_manager::map_host_physical(uefi_boot_physical_base_address));
    crt::set_memory(mapped_uefi_boot_base, 0, uefi_boot_image_size);
}

/**
 * @description 处理首次 VMExit 以及分阶段部署逻辑。
 * @param {void} 无。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * process_first_vmexit();
 */
void process_first_vmexit()
{
    static std::uint8_t is_first_vmexit = 1;

    if (is_first_vmexit == 1)
    {
        // 业务说明：首次 VMExit 初始化控制流，完成 SLAT、NMI、清理镜像与导出校验。
        // 输入：全局状态与配置；输出：组件初始化完成；规则：仅首次执行；异常：不抛出。
        logs::print("[Runtime] First VMExit captured. Taking control...\n");
        slat::process_first_vmexit();
        interrupts::set_up();
        clean_up_uefi_boot_image();

        // 业务说明：首次 VMExit 验证关键导出符号是否可解析。
        // 输入：ntoskrnl_base；输出：解析结果日志；规则：仅 ntoskrnl_base 非零时执行；异常：不抛出。
        if (ntoskrnl_base != 0)
        {
            const uint64_t pool_api = loader::get_kernel_export(ntoskrnl_base, "ExAllocatePoolWithTag");
            if (pool_api)
            {
                logs::print("[Step 1] Success: ExAllocatePoolWithTag = 0x%p\n", pool_api);
            }
            else
            {
                logs::print("[Step 1] ERROR: Failed to resolve ExAllocatePoolWithTag from 0x%p\n", ntoskrnl_base);
            }
        }

        is_first_vmexit = 0;
    }

    static uint8_t has_hidden_heap_pages = 0;
    static uint64_t vmexit_count = 0;

    // 业务说明：按 VMExit 次数触发堆页隐藏流程。
    // 输入：VMExit 计数；输出：隐藏状态；规则：达到阈值才执行；异常：不抛出。
    if (has_hidden_heap_pages == 0)
    {
        vmexit_count++;

        if (vmexit_count >= 5)
        {
            // 业务说明：达到阈值后隐藏堆页。
            // 输入：CR3 与阈值；输出：隐藏结果；规则：成功后标记完成；异常：不抛出。
            has_hidden_heap_pages = slat::hide_heap_pages(slat::hyperv_cr3());

            if (has_hidden_heap_pages == 1)
            {
                logs::print("[Runtime] Heap memory hiding complete (Total 2M VMExits threshold met).\n");
            }
        }
    }
}

/**
 * @description 用于提前返回的 VMExit 处理结果。
 * @param {void} 无。
 * @return {std::uint64_t} Intel VMExit 提前返回值。
 * @throws {无} 不抛出异常。
 * @example
 * return do_vmexit_premature_return();
 */
std::uint64_t do_vmexit_premature_return()
{
    return 0;
}

/**
 * @description 设置 VMExit 运行时状态与 UEFI 镜像信息。
 * @param {std::uint8_t*} original_vmexit_handler_routine 原始 VMExit 处理器地址。
 * @param {std::uint64_t} uefi_boot_physical_base_address_in UEFI Boot 镜像物理基址。
 * @param {std::uint64_t} uefi_boot_image_size_in UEFI Boot 镜像大小。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * set_vmexit_runtime_state(original_handler, uefi_base, uefi_size);
 */
void set_vmexit_runtime_state(std::uint8_t* original_vmexit_handler_routine, const std::uint64_t uefi_boot_physical_base_address_in, const std::uint64_t uefi_boot_image_size_in)
{
    // 业务说明：保存 VMExit 处理器与 UEFI 镜像信息，供清理流程使用。
    // 输入：原始 VMExit 处理器与镜像信息；输出：缓存状态；规则：入口阶段设置；异常：不抛出。
    original_vmexit_handler = original_vmexit_handler_routine;
    uefi_boot_physical_base_address = uefi_boot_physical_base_address_in;
    uefi_boot_image_size = uefi_boot_image_size_in;
}

/**
 * @description 设置 ntoskrnl 基址供 VMExit/导出解析使用。
 * @param {std::uint64_t} ntoskrnl_base_in ntoskrnl.exe 基址。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * set_ntoskrnl_base(ntoskrnl_base_from_uefi);
 */
void set_ntoskrnl_base(const std::uint64_t ntoskrnl_base_in)
{
    // 业务说明：记录 ntoskrnl 基址，供导出解析使用。
    // 输入：ntoskrnl_base_in；输出：缓存状态；规则：入口阶段设置；异常：不抛出。
    ntoskrnl_base = ntoskrnl_base_in;
}

/**
 * @description 获取当前 ntoskrnl 基址。
 * @param {void} 无。
 * @return {std::uint64_t} 当前保存的 ntoskrnl 基址。
 * @throws {无} 不抛出异常。
 * @example
 * const auto base = get_ntoskrnl_base();
 */
std::uint64_t get_ntoskrnl_base()
{
    return ntoskrnl_base;
}

/**
 * @description VMExit 入口函数，完成首次处理与分发逻辑。
 * @param {const std::uint64_t} a1 VMExit 参数1。
 * @param {const std::uint64_t} a2 VMExit 参数2。
 * @param {const std::uint64_t} a3 VMExit 参数3。
 * @param {const std::uint64_t} a4 VMExit 参数4。
 * @return {std::uint64_t} VMExit 返回值。
 * @throws {无} 不抛出异常。
 * @example
 * const auto result = vmexit_handler_detour(a1, a2, a3, a4);
 */
std::uint64_t vmexit_handler_detour(const std::uint64_t a1, const std::uint64_t a2, const std::uint64_t a3, const std::uint64_t a4)
{
    // 业务说明：处理首次 VMExit 并按退出原因进行分发。
    // 输入：VMExit 参数；输出：返回值或原处理器回调；规则：可提前返回；异常：不抛出。
    process_first_vmexit();

    const std::uint64_t exit_reason = arch::get_vmexit_reason();
    if (dispatch_vmexit(exit_reason, a1))
    {
        return do_vmexit_premature_return();
    }

    const auto original_vmexit_handler_function = reinterpret_cast<std::uint64_t(*)(std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t)>(original_vmexit_handler);
    return original_vmexit_handler_function(a1, a2, a3, a4);
}
