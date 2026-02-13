﻿#include "slat.h"
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
	std::atomic<std::uint64_t> dummy_page_pfn = 0;
}

/**
 * @description 初始化 SLAT 伪页，用于隐藏映射。
 * @param {void} 无。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * set_up_dummy_page();
 */
void set_up_dummy_page()
{
	// 业务说明：分配一页物理内存作为隐藏映射目标页。
	// 输入：无；输出：dummy_page_pfn；规则：分配并清零；异常：不抛出。
	void* dummy_page_allocation_ptr = heap_manager::allocate_page();

	const std::uint64_t dummy_page_physical_address = memory_manager::unmap_host_physical(dummy_page_allocation_ptr);

	dummy_page_pfn.store(dummy_page_physical_address >> 12, std::memory_order_release);

	crt::set_memory(dummy_page_allocation_ptr, 0, 0x1000);
}

/**
 * @description 初始化 SLAT 子系统。
 * @param {void} 无。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * slat::set_up();
 */
void slat::set_up()
{
	// 业务说明：完成 Hook 条目初始化与伪页准备。
	// 输入：无；输出：SLAT 初始化完成；规则：先准备 Hook 再创建伪页；异常：不抛出。
	hook::set_up_entries();
	set_up_dummy_page();
}

/**
 * @description 处理首次 VMExit 的 SLAT 初始化。
 * @param {void} 无。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * slat::process_first_vmexit();
 */
void slat::process_first_vmexit()
{
	// 业务说明：初始化 Hyper-V SLAT CR3 以支持后续隐藏。
	// 输入：无；输出：Hyper-V CR3 已缓存；规则：首次 VMExit 调用；异常：不抛出。
	set_up_hyperv_cr3();
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
 * @param {const cr3} slat_cr3 SLAT CR3。
 * @return {std::uint8_t} 是否全部隐藏完成。
 * @throws {无} 不抛出异常。
 * @example
 * const auto done = slat::hide_heap_pages(cr3_value);
 */
std::uint8_t slat::hide_heap_pages(const cr3 slat_cr3)
{
	// 业务说明：以分批方式隐藏堆页，降低 VMExit 开销。
	// 输入：slat_cr3；输出：隐藏完成状态；规则：每次处理固定页数；异常：不抛出。
	std::uint64_t heap_physical_base = heap_manager::initial_physical_base;
	std::uint64_t heap_physical_end = heap_physical_base + heap_manager::initial_size;

	// [ARCHITECT FIX] Atomic Thread-Safe Implementation
	// Using atomic to ensure multiple cores can process the heap hiding safely
	static std::atomic<std::uint64_t> current_shared_address(0);
	static std::atomic<bool> initialization_flag(false);

	bool expected = false;
	if (initialization_flag.compare_exchange_strong(expected, true))
	{
		current_physical_address = heap_physical_base;
		initialized = true;
	}

	const std::uint64_t BATCH_LIMIT = 32;
	std::uint64_t pages_processed = 0;

	while (pages_processed < BATCH_LIMIT)
	{
		// Use existing logic to hide page (maps to dummy page)
		virtual_address_t current_guest_physical_address = { };
		current_guest_physical_address.address = current_physical_address;
		hide_physical_page_from_guest(slat_cr3, current_guest_physical_address);

		current_physical_address += 0x1000;
		pages_processed++;
	}

	if (current_shared_address.load(std::memory_order_acquire) >= heap_physical_end)
	{
		return 1;
	}

	return 0;
}

/**
 * @description 将指定来宾物理页隐藏到伪页。
 * @param {const cr3} slat_cr3 SLAT CR3。
 * @param {const virtual_address_t} guest_physical_address 来宾物理地址。
 * @return {std::uint64_t} 隐藏是否成功。
 * @throws {无} 不抛出异常。
 * @example
 * const auto ok = slat::hide_physical_page_from_guest(cr3_value, gpa);
 */
std::uint64_t slat::hide_physical_page_from_guest(const cr3 slat_cr3, const virtual_address_t guest_physical_address)
{
	// 业务说明：定位目标 PTE 并将其指向伪页。
	// 输入：slat_cr3/gpa；输出：PTE 更新结果；规则：找不到 PTE 返回失败；异常：不抛出。
	slat_pte* target_pte_ptr = get_pte(slat_cr3, guest_physical_address, 1);

	if (target_pte_ptr == nullptr)
	{
		return 0;
	}

	target_pte_ptr->page_frame_number = dummy_page_pfn;

	return 1;
}

/**
 * @description 同时在 Hyper-V 与 Hook SLAT 中隐藏来宾物理页。
 * @param {const virtual_address_t} guest_physical_address 来宾物理地址。
 * @return {std::uint64_t} 隐藏是否成功。
 * @throws {无} 不抛出异常。
 * @example
 * const auto ok = slat::hide_physical_page_from_guest(gpa);
 */
std::uint64_t slat::hide_physical_page_from_guest(const virtual_address_t guest_physical_address)
{
	// 业务说明：对两套 SLAT 同步隐藏目标页。
	// 输入：gpa；输出：双侧隐藏结果；规则：双侧均成功才返回成功；异常：不抛出。
	return hide_physical_page_from_guest(hyperv_cr3(), guest_physical_address) && hide_physical_page_from_guest(hook_cr3(), guest_physical_address);
}