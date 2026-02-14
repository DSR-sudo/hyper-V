#include "slat.h"
#include "../memory_manager/memory_manager.h"
#include "../memory_manager/heap_manager.h"
#include "../crt/crt.h"
#include <ia32-doc/ia32.hpp>
#include "../arch/arch.h"
#include "cr3/cr3.h"
#include "cr3/pte.h"
#include "hook/hook.h"
#include "slat_def.h"
#include <cstdint>

#include <atomic>

namespace
{
	// 业务说明：私有变量已移除，转而使用 context_t 传递状态。
}

/**
 * @description 初始化 SLAT 伪页，用于隐藏映射。
 * @param {slat::context_t*} ctx SLAT 上下文。
 * @param {heap_manager::context_t*} heap_ctx 堆上下文。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * set_up_dummy_page(ctx, heap_ctx);
 */
void set_up_dummy_page(slat::context_t* ctx, heap_manager::context_t* heap_ctx)
{
	// 业务说明：分配一页物理内存作为隐藏映射目标页。
	// 输入：ctx；输出：ctx->dummy_page_pfn；规则：分配并清零；异常：不抛出。
	void* dummy_page_allocation_ptr = heap_manager::allocate_page(heap_ctx);

	const std::uint64_t dummy_page_physical_address = memory_manager::unmap_host_physical(dummy_page_allocation_ptr);

	ctx->dummy_page_pfn.store(dummy_page_physical_address >> 12, std::memory_order_release);

	crt::set_memory(dummy_page_allocation_ptr, 0, 0x1000);
}

/**
 * @description 初始化 SLAT 子系统。
 * @param {slat::context_t*} ctx SLAT 上下文。
 * @param {heap_manager::context_t*} heap_ctx 堆上下文。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * slat::set_up(ctx, heap_ctx);
 */
void slat::set_up(context_t* ctx, heap_manager::context_t* heap_ctx)
{
	// 业务说明：完成 Hook 条目初始化与伪页准备。
	// 输入：ctx；输出：SLAT 初始化完成；规则：先准备 Hook 再创建伪页；异常：不抛出。
	ctx->heap_ctx = heap_ctx;
	ctx->is_first_slat_hook = 1;
	ctx->available_hook_list_head = nullptr;
	ctx->used_hook_list_head = nullptr;
	hook::set_up_entries(ctx, heap_ctx);
	set_up_dummy_page(ctx, heap_ctx);
}

/**
 * @description 处理首次 VMExit 的 SLAT 初始化。
 * @param {slat::context_t*} ctx SLAT 上下文。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * slat::process_first_vmexit(ctx);
 */
void slat::process_first_vmexit(context_t* ctx)
{
	// 业务说明：初始化 Hyper-V SLAT CR3 以支持后续隐藏。
	// 输入：ctx；输出：Hyper-V CR3 已缓存；规则：首次 VMExit 调用；异常：不抛出。
	set_up_hyperv_cr3(ctx);
}

/**
 * @description 转换来宾物理地址为宿主映射地址。
 * @param {const cr3} slat_cr3 SLAT CR3。
 * @param {const virtual_address_t} guest_physical_address 来宾物理地址。
 * @param {std::uint64_t* const} size_left_of_page 可选输出剩余页内大小。
 * @return {std::uint64_t} 转换后的宿主地址。
 * @throws {无} 不抛出异常。
 * @example
 * const auto host_va = slat::translate_guest_physical_address(cr3_value, gpa, &size_left);
 */
std::uint64_t slat::translate_guest_physical_address(const cr3 slat_cr3, const virtual_address_t guest_physical_address, std::uint64_t* const size_left_of_page)
{
	// 业务说明：使用内存管理器执行地址转换。
	// 输入：slat_cr3/gpa；输出：宿主地址；规则：按 SLAT 规则转换；异常：不抛出。
	return memory_manager::translate_host_virtual_address(slat_cr3, guest_physical_address, size_left_of_page);
}

/**
 * @description 按批次隐藏堆页的 SLAT 映射。
 * @param {slat::context_t*} ctx SLAT 上下文.
 * @param {const cr3} slat_cr3 SLAT CR3.
 * @param {const std::uint64_t} heap_base 堆起始物理地址。
 * @param {const std::uint64_t} heap_size 堆大小。
 * @return {std::uint8_t} 是否全部隐藏完成。
 * @throws {无} 不抛出异常。
 * @example
 * const auto done = slat::hide_heap_pages(ctx, cr3_value, base, size);
 */
std::uint8_t slat::hide_heap_pages(context_t* ctx, const cr3 slat_cr3, const std::uint64_t heap_base, const std::uint64_t heap_size)
{
	// 业务说明：以分批方式隐藏堆页，降低 VMExit 开销。
	// 输入：slat_cr3；输出：隐藏完成状态；规则：每次处理固定页数；异常：不抛出。
	const std::uint64_t heap_physical_base = heap_base;
	const std::uint64_t heap_physical_end = heap_base + heap_size;

	// [ARCHITECT FIX] Atomic Thread-Safe Implementation
	// Using atomic to ensure multiple cores can process the heap hiding safely
	bool expected = false;
	if (ctx->initialization_flag.compare_exchange_strong(expected, true))
	{
		ctx->current_shared_address.store(heap_physical_base, std::memory_order_release);
	}

	const std::uint64_t BATCH_LIMIT = 32;
	std::uint64_t pages_processed = 0;

	while (pages_processed < BATCH_LIMIT)
	{
		const std::uint64_t current_physical_address = ctx->current_shared_address.fetch_add(0x1000, std::memory_order_acq_rel);

		if (current_physical_address >= heap_physical_end)
		{
			break;
		}

		virtual_address_t current_guest_physical_address = { };
		current_guest_physical_address.address = current_physical_address;
		hide_physical_page_from_guest(ctx, slat_cr3, current_guest_physical_address);

		pages_processed++;
	}

	if (ctx->current_shared_address.load(std::memory_order_acquire) >= heap_physical_end)
	{
		return 1;
	}

	return 0;
}

/**
 * @description 将指定来宾物理页隐藏到伪页。
 * @param {slat::context_t*} ctx SLAT 上下文。
 * @param {const cr3} slat_cr3 SLAT CR3。
 * @param {const virtual_address_t} guest_physical_address 来宾物理地址。
 * @return {std::uint64_t} 隐藏是否成功。
 * @throws {无} 不抛出异常。
 * @example
 * const auto ok = slat::hide_physical_page_from_guest(ctx, cr3_value, gpa);
 */
std::uint64_t slat::hide_physical_page_from_guest(context_t* ctx, const cr3 slat_cr3, const virtual_address_t guest_physical_address)
{
	// 业务说明：定位目标 PTE 并将其指向伪页。
	// 输入：slat_cr3/gpa；输出：PTE 更新结果；规则：找不到 PTE 返回失败；异常：不抛出。
	slat_pte* target_pte_ptr = get_pte(slat_cr3, guest_physical_address, ctx->heap_ctx, 1);

	if (target_pte_ptr == nullptr)
	{
		return 0;
	}

	target_pte_ptr->page_frame_number = ctx->dummy_page_pfn.load(std::memory_order_acquire);

	return 1;
}

/**
 * @description 同时在 Hyper-V 与 Hook SLAT 中隐藏来宾物理页。
 * @param {slat::context_t*} ctx SLAT 上下文。
 * @param {const virtual_address_t} guest_physical_address 来宾物理地址。
 * @return {std::uint64_t} 隐藏是否成功。
 * @throws {无} 不抛出异常。
 * @example
 * const auto ok = slat::hide_physical_page_from_guest(ctx, gpa);
 */
std::uint64_t slat::hide_physical_page_from_guest(context_t* ctx, const virtual_address_t guest_physical_address)
{
	// 业务说明：对两套 SLAT 同步隐藏目标页。
	// 输入：gpa；输出：双侧隐藏结果；规则：双侧均成功才返回成功；异常：不抛出。
	return hide_physical_page_from_guest(ctx, ctx->hyperv_slat_cr3, guest_physical_address) && hide_physical_page_from_guest(ctx, ctx->hook_slat_cr3, guest_physical_address);
}
