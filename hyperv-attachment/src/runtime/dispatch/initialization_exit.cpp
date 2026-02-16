#include "initialization_exit.h"
#include "../runtime_context.h"
#include "../../modules/slat/slat.h"
#include "../../modules/slat/cr3/cr3.h"
#include "../../modules/interrupts/interrupts.h"
#include "../../modules/loader/imports.h"
#include "../../modules/logs/logs.h"
#include "../../modules/memory_manager/memory_manager.h"
#include "../../modules/crt/crt.h"
#include "../../modules/arch/arch.h"

void clean_up_uefi_boot_image()
{
    // 业务说明：通过 Host 物理映射清理 UEFI 启动镜像内容，降低残留痕迹。
    // 输入：uefi_boot_physical_base_address 与 uefi_boot_image_size；输出：清零后的物理内存；规则：仅在有效映射后写零；异常：不抛出。
    const auto mapped_uefi_boot_base = static_cast<std::uint8_t*>(memory_manager::map_host_physical(g_runtime_context.uefi_boot_physical_base_address));
    crt::set_memory(mapped_uefi_boot_base, 0, g_runtime_context.uefi_boot_image_size);
}

void process_first_vmexit()
{
    if (g_runtime_context.is_first_vmexit == 1)
    {
        // 业务说明：首次 VMExit 初始化控制流，完成 SLAT、NMI、清理镜像与导出校验。
        // 输入：全局状态与配置；输出：组件初始化完成；规则：仅首次执行；异常：不抛出。
        logs::print(&g_runtime_context.log_ctx, "[Runtime] First VMExit captured. Taking control...\n"); // 打印日志，记录首次捕获到 VMExit，接管控制流
        slat::process_first_vmexit(&g_runtime_context.slat_ctx); // 初始化 SLAT 并在首次 VMExit 时建立页表映射
        g_runtime_context.loader_ctx.guest_cr3 = arch::get_guest_cr3(); // 获取并保存来宾机（Guest）当前的 CR3 寄存器值
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
