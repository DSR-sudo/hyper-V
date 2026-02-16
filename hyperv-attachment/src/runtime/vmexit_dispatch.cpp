#include <intrin.h>
#include "vmexit_dispatch.h"

#include "../modules/arch/arch.h"
#include "../modules/crt/crt.h"
#include "../hypercall/hypercall.h"
#include <hypercall/hypercall_def.h>
#include "../modules/interrupts/interrupts.h"
#include "../modules/loader/imports.h"
#include "../modules/logs/logs.h"
#include "../modules/memory_manager/memory_manager.h"
#include "../modules/slat/slat.h"
#include "../modules/slat/cr3/cr3.h"
#include "../modules/slat/violation/violation.h"
#include "../manager/loader/deployer.h"
#include "../modules/apic/apic.h"
#include "../../shared/structures/trap_frame.h"

#include "runtime_context.h"

// New includes for dispatched handlers
#include "dispatch/hypercall_exit.h"
#include "dispatch/injection_exit.h"
#include "dispatch/initialization_exit.h"

namespace
{
    // 业务说明：全局状态已移至 g_runtime_context。
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
    trap_frame_t* const trap_frame = *reinterpret_cast<trap_frame_t**>(a1);

    // 1. 全局业务逻辑 Tick (注入状态机)
    //    将所有“非 Exit Reason 触发”的逻辑移入此处
    if (process_injection_state_tick(arch::get_guest_rip(), trap_frame))
    {
        return true; // Magic Trap 命中，直接返回
    }

    // 2. Exception Handling (#DB for Injection)
    if (exit_reason == 0) // Exception or NMI
    {
         size_t intr_info;
         __vmx_vmread(0x4404, &intr_info); // VM_EXIT_INTR_INFO
         if ((intr_info & 0x80000000) && (intr_info & 0xFF) == 1) // Valid + Vector 1 (#DB)
         {
             if (handle_injection_db_exit(trap_frame))
             {
                 return true;
             }
         }
    }

    // 3. 根据 Exit Reason 分发
    if (arch::is_cpuid(exit_reason))
    {
        return try_process_hypercall_exit(a1);
    }

    if (arch::is_slat_violation(exit_reason))
    {
        // 保持原有逻辑，或者也封装进 slat::process_violation
        return slat::violation::process(&g_runtime_context.slat_ctx) == 1;
    }

    if (arch::is_non_maskable_interrupt_exit(exit_reason))
    {
        interrupts::process_nmi(&g_runtime_context.interrupts_ctx);
        return false;
    }

    if (arch::is_mtf_exit(exit_reason))
    {
        // 常规 MTF 处理（SLAT trace 等）
        slat::violation::handle_mtf(&g_runtime_context.slat_ctx);
        return true;
    }

    return false;
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
    g_runtime_context.original_vmexit_handler = original_vmexit_handler_routine;
    g_runtime_context.uefi_boot_physical_base_address = uefi_boot_physical_base_address_in;
    g_runtime_context.uefi_boot_image_size = uefi_boot_image_size_in;
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
    g_runtime_context.ntoskrnl_base = ntoskrnl_base_in;
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
    return g_runtime_context.ntoskrnl_base;
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

    const auto original_vmexit_handler_function = reinterpret_cast<std::uint64_t(*)(std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t)>(g_runtime_context.original_vmexit_handler);
    return original_vmexit_handler_function(a1, a2, a3, a4);
}
