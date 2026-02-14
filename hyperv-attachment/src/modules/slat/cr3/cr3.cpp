#include "cr3.h"

#include "../slat.h"
#include "../slat_def.h"
#include "deep_copy.h"
#include "pte.h"
#include <ia32-doc/ia32.hpp>

#include "../../memory_manager/memory_manager.h"
#include "../../memory_manager/heap_manager.h"
#include "../../../runtime/runtime_context.h"
#include "../../interrupts/interrupts.h"
#include "../../arch/arch.h"

#ifdef _INTELMACHINE
extern "C" void invalidate_ept_mappings(invept_type type, const invept_descriptor& descriptor);
#endif

namespace
{
	// 业务说明：私有变量已移除，转而使用 context_t 传递状态。
}

/**
 * @description 获取 Hyper-V SLAT CR3。
 * @param {slat::context_t*} ctx SLAT 上下文。
 * @return {cr3} Hyper-V SLAT CR3。
 * @throws {无} 不抛出异常。
 * @example
 * const auto cr3_value = slat::hyperv_cr3(ctx);
 */
cr3 slat::hyperv_cr3(context_t* ctx)
{
	// 业务说明：返回已缓存的 Hyper-V CR3。
	// 输入：ctx；输出：CR3 值；规则：返回当前缓存；异常：不抛出。
	return ctx->hyperv_slat_cr3;
}

/**
 * @description 获取 Hook SLAT CR3。
 * @param {slat::context_t*} ctx SLAT 上下文。
 * @return {cr3} Hook SLAT CR3。
 * @throws {无} 不抛出异常。
 * @example
 * const auto cr3_value = slat::hook_cr3(ctx);
 */
cr3 slat::hook_cr3(context_t* ctx)
{
	// 业务说明：返回已缓存的 Hook CR3。
	// 输入：ctx；输出：CR3 值；规则：返回当前缓存；异常：不抛出。
	return ctx->hook_slat_cr3;
}

/**
 * @description 获取当前 CPU 的 SLAT CR3。
 * @param {void} 无。
 * @return {cr3} 当前 SLAT CR3。
 * @throws {无} 不抛出异常。
 * @example
 * const auto cr3_value = slat::get_cr3();
 */
cr3 slat::get_cr3()
{
	// 业务说明：从架构层读取当前 SLAT CR3。
	// 输入：无；输出：CR3 值；规则：读取 VMCS；异常：不抛出。
	return arch::get_slat_cr3();
}

/**
 * @description 设置当前 CPU 的 SLAT CR3。
 * @param {const cr3} slat_cr3 目标 SLAT CR3。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * slat::set_cr3(cr3_value);
 */
void slat::set_cr3(const cr3 slat_cr3)
{
	// 业务说明：写入 SLAT CR3 并刷新 EPT 缓存。
	// 输入：slat_cr3；输出：CR3 生效；规则：设置后执行 INVEPT；异常：不抛出。
	arch::set_slat_cr3(slat_cr3);

	invept_single_context(slat_cr3);
}

/**
 * @description 刷新当前 EPT 上下文缓存。
 * @param {const cr3} slat_cr3 目标 SLAT CR3。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * slat::invept_single_context(cr3_value);
 */
void slat::invept_single_context(const cr3 slat_cr3)
{
#ifdef _INTELMACHINE
	// 业务说明：使用 INVEPT 指令刷新指定 EPT 上下文。
	// 输入：slat_cr3；输出：EPT 缓存刷新；规则：Intel 平台执行；异常：不抛出。
	invept_descriptor invept_desc = { };
	invept_desc.ept_pointer = slat_cr3.flags;
	invept_desc.reserved = 0;
	invalidate_ept_mappings(invept_type::invept_single_context, invept_desc);
#endif
}

/**
 * @description 刷新当前处理器的 TLB/EPT 缓存。
 * @param {const std::uint8_t} has_slat_cr3_changed 是否已更改 SLAT CR3。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * slat::flush_current_logical_processor_cache(1);
 */
void slat::flush_current_logical_processor_cache(const std::uint8_t has_slat_cr3_changed)
{
#ifdef _INTELMACHINE
	// 业务说明：Intel 平台使用 INVEPT 刷新当前上下文。
	// 输入：has_slat_cr3_changed；输出：缓存刷新；规则：忽略参数；异常：不抛出。
	(void)has_slat_cr3_changed;
	invept_single_context(get_cr3());
#else
	// 业务说明：AMD 平台配置 VMCB 刷新 TLB，并视 CR3 是否变化清理标志。
	// 输入：has_slat_cr3_changed；输出：TLB 刷新指令；规则：变化时清理嵌套分页标志；异常：不抛出。
	vmcb_t* const vmcb = arch::get_vmcb();

	vmcb->control.tlb_control = tlb_control_t::flush_guest_tlb_entries;

	if (has_slat_cr3_changed == 1)
	{
		vmcb->control.clean.nested_paging = 0;
	}
#endif
}

/**
 * @description 刷新所有处理器的 TLB/EPT 缓存。
 * @param {void} 无。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * slat::flush_all_logical_processors_cache();
 */
void slat::flush_all_logical_processors_cache()
{
	// 业务说明：刷新当前处理器缓存并触发其他处理器 NMI 刷新。
	// 输入：无；输出：全核缓存刷新；规则：发送 NMI；异常：不抛出。
	flush_current_logical_processor_cache();

	interrupts::set_all_nmi_ready(&g_runtime_context.interrupts_ctx);
	interrupts::send_nmi_all_but_self(&g_runtime_context.interrupts_ctx);
}

/**
 * @description 初始化 SLAT CR3 与 PML4 表。
 * @param {slat::context_t*} ctx SLAT 上下文。
 * @param {cr3* const} slat_cr3 输出 SLAT CR3。
 * @param {slat_pml4e** const} slat_pml4 输出 PML4 表指针。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * set_up_slat_cr3(ctx, &cr3_value, &pml4_ptr);
 */
void set_up_slat_cr3(slat::context_t* ctx, cr3* const slat_cr3, slat_pml4e** const slat_pml4)
{
	// 业务说明：分配并清零 PML4 表，构建新的 SLAT CR3。
	// 输入：ctx/slat_cr3/slat_pml4；输出：PML4 表与 CR3 更新；规则：按页分配；异常：不抛出。
	*slat_pml4 = static_cast<slat_pml4e*>(heap_manager::allocate_page(ctx->heap_ctx));

	crt::set_memory(*slat_pml4, 0, sizeof(slat_pml4e) * 512);

	const std::uint64_t pml4_physical_address = memory_manager::unmap_host_physical(*slat_pml4);

	*slat_cr3 = slat::hyperv_cr3(ctx);
	slat_cr3->address_of_page_directory = pml4_physical_address >> 12;
}

/**
 * @description 缓存 Hyper-V SLAT CR3。
 * @param {slat::context_t*} ctx SLAT 上下文。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * slat::set_up_hyperv_cr3(ctx);
 */
void slat::set_up_hyperv_cr3(context_t* ctx)
{
	// 业务说明：读取当前 SLAT CR3 作为 Hyper-V CR3。
	// 输入：ctx；输出：ctx->hyperv_slat_cr3 更新；规则：读取 VMCS；异常：不抛出。
	ctx->hyperv_slat_cr3 = get_cr3();
}

/**
 * @description 初始化 Hook SLAT CR3。
 * @param {slat::context_t*} ctx SLAT 上下文。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * slat::set_up_hook_cr3(ctx);
 */
void slat::set_up_hook_cr3(context_t* ctx)
{
	// 业务说明：分配并初始化 Hook SLAT PML4 及其 CR3。
	// 输入：ctx；输出：ctx->hook_slat_cr3/hook_slat_pml4 更新；规则：深拷贝原表；异常：不抛出。
	set_up_slat_cr3(ctx, &ctx->hook_slat_cr3, reinterpret_cast<slat_pml4e**>(&ctx->hook_slat_pml4));

	make_pml4_copy(reinterpret_cast<slat_pml4e*>(memory_manager::map_host_physical(ctx->hyperv_slat_cr3.address_of_page_directory << 12)), reinterpret_cast<slat_pml4e*>(ctx->hook_slat_pml4), ctx->heap_ctx, 0);
}
