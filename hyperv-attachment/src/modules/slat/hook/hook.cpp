#include "hook.h"
#include "hook_entry.h"

#include "../cr3/cr3.h"
#include "../cr3/pte.h"
#include "../slat_def.h"
#include "../slat.h"

#include "../../memory_manager/heap_manager.h"

#include "../../structures/virtual_address.h"
#include "../../crt/crt.h"

/**
 * @description 处理首次 SLAT Hook 初始化。
 * @param {slat::context_t*} ctx SLAT 上下文。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * process_first_slat_hook(ctx);
 */
static void process_first_slat_hook(slat::context_t* ctx)
{
	// 业务说明：仅在首次 Hook 时初始化 Hook SLAT CR3。
	// 输入：ctx；输出：Hook CR3 初始化；规则：仅首次执行；异常：不抛出。
	if (ctx->is_first_slat_hook)
	{
		ctx->is_first_slat_hook = 0;

		slat::set_up_hook_cr3(ctx);
	}
}

/**
 * @description 初始化 Hook 条目池。
 * @param {slat::context_t*} ctx SLAT 上下文。
 * @param {heap_manager::context_t*} heap_ctx 堆上下文。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * slat::hook::set_up_entries(ctx, heap_ctx);
 */
void slat::hook::set_up_entries(slat::context_t* ctx, heap_manager::context_t* heap_ctx)
{
	// 业务说明：分配一页内存作为条目池并构建空闲链表。
	// 输入：heap_ctx；输出：available_hook_list_head；规则：按条目大小链入；异常：不抛出。
	constexpr std::uint64_t hook_entries_wanted = 0x1000 / sizeof(entry_t);

	void* const hook_entries_allocation = heap_manager::allocate_page(heap_ctx);

	ctx->available_hook_list_head = static_cast<entry_t*>(hook_entries_allocation);
	ctx->used_hook_list_head = nullptr;

	entry_t* current_entry = ctx->available_hook_list_head;

	for (std::uint64_t i = 0; i < hook_entries_wanted - 1; i++)
	{
		current_entry->set_next(current_entry + 1);
		current_entry->set_original_pfn(0);

		current_entry = current_entry->next();
	}

	current_entry->set_original_pfn(0);
	current_entry->set_next(nullptr);
}

/**
 * @description 添加 SLAT Hook 条目并建立影子页映射。
 * @param {slat::context_t*} ctx SLAT 上下文。
 * @param {const virtual_address_t} target_guest_physical_address 目标来宾物理地址。
 * @param {const virtual_address_t} shadow_guest_physical_address 影子来宾物理地址。
 * @return {std::uint64_t} 是否添加成功。
 * @throws {无} 不抛出异常。
 * @example
 * const auto ok = slat::hook::add(ctx, target_gpa, shadow_gpa);
 */
std::uint64_t slat::hook::add(slat::context_t* ctx, const virtual_address_t target_guest_physical_address, const virtual_address_t shadow_guest_physical_address)
{
	// 业务说明：加锁确保 Hook 条目修改的并发安全。
	// 输入：ctx/目标/影子地址；输出：Hook 安装结果；规则：失败返回 0；异常：不抛出。
	ctx->hook_mutex.lock();

	process_first_slat_hook(ctx);

	const entry_t* const already_present_hook_entry = entry_t::find(ctx, target_guest_physical_address.address >> 12);

	if (already_present_hook_entry != nullptr)
	{
		ctx->hook_mutex.release();

		return 0;
	}

	std::uint8_t paging_split_state = 0;

	// 业务说明：获取目标页的 Hyper-V 与 Hook PTE，确定拆分页状态。
	// 输入：目标地址；输出：PTE 指针与拆分状态；规则：找不到返回失败；异常：不抛出。
	slat_pte* const target_pte = get_pte(hyperv_cr3(ctx), target_guest_physical_address, ctx->heap_ctx, 1, &paging_split_state);

	if (target_pte == nullptr)
	{
		ctx->hook_mutex.release();

		return 0;
	}

	slat_pte* const hook_target_pte = get_pte(hook_cr3(ctx), target_guest_physical_address, ctx->heap_ctx, 1);

	if (hook_target_pte == nullptr)
	{
		ctx->hook_mutex.release();

		return 0;
	}

	if (paging_split_state == 0)
	{
		// 业务说明：复用同 2MB 范围的拆分页状态，避免重复拆分。
		// 输入：目标 PFN；输出：paging_split_state；规则：已有条目则继承；异常：不抛出。
		const entry_t* const similar_space_hook_entry = entry_t::find_in_2mb_range(ctx, target_guest_physical_address.address >> 12);

		if (similar_space_hook_entry != nullptr)
		{
			paging_split_state = static_cast<std::uint8_t>(similar_space_hook_entry->paging_split_state());
		}
	}

	// 业务说明：转换影子页地址，确保可用于映射。
	// 输入：shadow_guest_physical_address；输出：宿主物理地址；规则：失败返回 0；异常：不抛出。
	const std::uint64_t shadow_page_host_physical_address = translate_guest_physical_address(hyperv_cr3(ctx), shadow_guest_physical_address);


	if (shadow_page_host_physical_address == 0)
	{
		ctx->hook_mutex.release();

		return 0;
	}

	// 业务说明：从空闲链表中分配一个 Hook 条目。
	// 输入：无；输出：hook_entry；规则：为空则失败；异常：不抛出。
	entry_t* const hook_entry = ctx->available_hook_list_head;

	if (hook_entry == nullptr)
	{
		ctx->hook_mutex.release();

		return 0;
	}

	ctx->available_hook_list_head = hook_entry->next();

	// 业务说明：填充 Hook 条目并插入已用链表。
	// 输入：hook_entry；输出：链表更新；规则：头插入；异常：不抛出。
	hook_entry->set_next(ctx->used_hook_list_head);
	hook_entry->set_original_pfn(target_pte->page_frame_number);
	hook_entry->set_paging_split_state(paging_split_state);

	ctx->used_hook_list_head = hook_entry;

	// 业务说明：Intel 平台保存原访问权限并配置影子页映射与权限切换。
	// 输入：target_pte/hook_target_pte；输出：PTE 权限更新；规则：目标页仅可执行；异常：不抛出。
	hook_entry->set_original_read_access(target_pte->read_access);
	hook_entry->set_original_write_access(target_pte->write_access);
	hook_entry->set_original_execute_access(target_pte->execute_access);

	target_pte->page_frame_number = shadow_page_host_physical_address >> 12;
	target_pte->execute_access = 1;
	target_pte->read_access = 0;
	target_pte->write_access = 0;

	hook_target_pte->execute_access = 0;
	hook_target_pte->read_access = 1;
	hook_target_pte->write_access = 1;

	ctx->hook_mutex.release();

	// 业务说明：仅刷新当前核心缓存，避免全核 NMI 导致超时。
	// 输入：无；输出：TLB/EPT 刷新；规则：仅当前核心；异常：不抛出。
	flush_current_logical_processor_cache();

	return 1;
}

std::uint64_t slat::hook::hide_payload_memory(slat::context_t* ctx, const virtual_address_t target_guest_physical_address)
{
	ctx->hook_mutex.lock();

	process_first_slat_hook(ctx);

	const entry_t* const already_present = entry_t::find(ctx, target_guest_physical_address.address >> 12);

	if (already_present != nullptr)
	{
		ctx->hook_mutex.release();

		return 0;
	}

	std::uint8_t paging_split_state = 0;
	slat_pte* const target_pte = get_pte(hyperv_cr3(ctx), target_guest_physical_address, ctx->heap_ctx, 1, &paging_split_state);
	slat_pte* const hook_target_pte = get_pte(hook_cr3(ctx), target_guest_physical_address, ctx->heap_ctx, 1);

	if (target_pte == nullptr || hook_target_pte == nullptr)
	{
		ctx->hook_mutex.release();

		return 0;
	}

	entry_t* const hook_entry = ctx->available_hook_list_head;

	if (hook_entry == nullptr)
	{
		ctx->hook_mutex.release();

		return 0;
	}

	ctx->available_hook_list_head = hook_entry->next();
	hook_entry->set_next(ctx->used_hook_list_head);
	hook_entry->set_original_pfn(target_pte->page_frame_number);
	hook_entry->set_paging_split_state(paging_split_state);
	ctx->used_hook_list_head = hook_entry;

	hook_entry->set_original_read_access(target_pte->read_access);
	hook_entry->set_original_write_access(target_pte->write_access);
	hook_entry->set_original_execute_access(target_pte->execute_access);

	// 【核心逻辑】：Primary EPT 指向真实内存，但仅允许执行 (R=0, 触发读取拦截)
	target_pte->execute_access = 1;
	target_pte->read_access = 0;
	target_pte->write_access = 0;

	// 【核心逻辑】：Secondary EPT 指向全 0 伪页，仅允许读取 (ACE 扫描时拿到的数据)
	hook_target_pte->page_frame_number = ctx->dummy_page_pfn.load(std::memory_order_acquire);
	hook_target_pte->execute_access = 0;
	hook_target_pte->read_access = 1;
	hook_target_pte->write_access = 0;

	ctx->hook_mutex.release();

	flush_current_logical_processor_cache();

	return 1;
}

/**
 * @description 添加 SLAT Hook 条目并建立影子页映射（直接使用宿主物理地址）。
 * @param {slat::context_t*} ctx SLAT 上下文。
 * @param {const virtual_address_t} target_guest_physical_address 目标来宾物理地址。
 * @param {const std::uint64_t} shadow_host_physical_address 影子宿主物理地址。
 * @return {std::uint64_t} 是否添加成功。
 * @throws {无} 不抛出异常。
 * @example
 * const auto ok = slat::hook::add_by_host_physical(ctx, target_gpa, shadow_hpa);
 */
std::uint64_t slat::hook::add_by_host_physical(slat::context_t* ctx, const virtual_address_t target_guest_physical_address, const std::uint64_t shadow_host_physical_address)
{
	// 业务说明：加锁确保 Hook 条目修改的并发安全。
	// 输入：ctx/目标/影子地址；输出：Hook 安装结果；规则：失败返回 0；异常：不抛出。
	ctx->hook_mutex.lock();

	process_first_slat_hook(ctx);

	const entry_t* const already_present_hook_entry = entry_t::find(ctx, target_guest_physical_address.address >> 12);

	if (already_present_hook_entry != nullptr)
	{
		ctx->hook_mutex.release();

		return 0;
	}

	std::uint8_t paging_split_state = 0;

	// 业务说明：获取目标页的 Hyper-V 与 Hook PTE，确定拆分页状态。
	// 输入：目标地址；输出：PTE 指针与拆分状态；规则：找不到返回失败；异常：不抛出。
	slat_pte* const target_pte = get_pte(hyperv_cr3(ctx), target_guest_physical_address, ctx->heap_ctx, 1, &paging_split_state);

	if (target_pte == nullptr)
	{
		ctx->hook_mutex.release();

		return 0;
	}

	slat_pte* const hook_target_pte = get_pte(hook_cr3(ctx), target_guest_physical_address, ctx->heap_ctx, 1);

	if (hook_target_pte == nullptr)
	{
		ctx->hook_mutex.release();

		return 0;
	}

	if (paging_split_state == 0)
	{
		// 业务说明：复用同 2MB 范围的拆分页状态，避免重复拆分。
		// 输入：目标 PFN；输出：paging_split_state；规则：已有条目则继承；异常：不抛出。
		const entry_t* const similar_space_hook_entry = entry_t::find_in_2mb_range(ctx, target_guest_physical_address.address >> 12);

		if (similar_space_hook_entry != nullptr)
		{
			paging_split_state = static_cast<std::uint8_t>(similar_space_hook_entry->paging_split_state());
		}
	}

	// 业务说明：直接使用传入的影子页宿主物理地址。
	// 输入：shadow_host_physical_address；输出：宿主物理地址；规则：无转换；异常：不抛出。
	const std::uint64_t shadow_page_host_physical_address = shadow_host_physical_address;


	if (shadow_page_host_physical_address == 0)
	{
		ctx->hook_mutex.release();

		return 0;
	}

	// 业务说明：从空闲链表中分配一个 Hook 条目。
	// 输入：无；输出：hook_entry；规则：为空则失败；异常：不抛出。
	entry_t* const hook_entry = ctx->available_hook_list_head;

	if (hook_entry == nullptr)
	{
		ctx->hook_mutex.release();

		return 0;
	}

	ctx->available_hook_list_head = hook_entry->next();

	// 业务说明：填充 Hook 条目并插入已用链表。
	// 输入：hook_entry；输出：链表更新；规则：头插入；异常：不抛出。
	hook_entry->set_next(ctx->used_hook_list_head);
	hook_entry->set_original_pfn(target_pte->page_frame_number);
	hook_entry->set_paging_split_state(paging_split_state);

	ctx->used_hook_list_head = hook_entry;

	// 业务说明：Intel 平台保存原访问权限并配置影子页映射与权限切换。
	// 输入：target_pte/hook_target_pte；输出：PTE 权限更新；规则：目标页仅可执行；异常：不抛出。
	hook_entry->set_original_read_access(target_pte->read_access);
	hook_entry->set_original_write_access(target_pte->write_access);
	hook_entry->set_original_execute_access(target_pte->execute_access);

	target_pte->page_frame_number = shadow_page_host_physical_address >> 12;
	target_pte->execute_access = 1;
	target_pte->read_access = 0;
	target_pte->write_access = 0;

	hook_target_pte->execute_access = 0;
	hook_target_pte->read_access = 1;
	hook_target_pte->write_access = 1;

	ctx->hook_mutex.release();

	// 业务说明：仅刷新当前核心缓存，避免全核 NMI 导致超时。
	// 输入：无；输出：TLB/EPT 刷新；规则：仅当前核心；异常：不抛出。
	flush_current_logical_processor_cache();

	return 1;
}

/**
 * @description 判断 Hook 是否需要合并 2MB 页表。
 * @param {slat::context_t*} ctx SLAT 上下文。
 * @param {const slat::hook::entry_t* const} hook_entry Hook 条目。
 * @param {const virtual_address_t} guest_physical_address 目标来宾物理地址。
 * @return {std::uint8_t} 是否需要合并。
 * @throws {无} 不抛出异常。
 * @example
 * const auto need = does_hook_need_merge(entry, gpa);
 */
std::uint8_t does_hook_need_merge(slat::context_t* ctx, const slat::hook::entry_t* const hook_entry, const virtual_address_t guest_physical_address)
{
	// 业务说明：仅当条目处于拆分页状态且范围内无其他 Hook 时才合并。
	// 输入：hook_entry/gpa；输出：是否需要合并；规则：范围内无其他 Hook；异常：不抛出。
	if (hook_entry == nullptr)
	{
		return 0;
	}

	const std::uint8_t requires_merge = hook_entry->paging_split_state() == 1;

	if (requires_merge == 0)
	{
		return 0;
	}

	const slat::hook::entry_t* const other_hook = slat::hook::entry_t::find_in_2mb_range(ctx, guest_physical_address.address >> 12, hook_entry);

	return other_hook == nullptr;
}

/**
 * @description 清理 Hook 相关 PTE 并恢复原始权限。
 * @param {const virtual_address_t} target_guest_physical_address 目标来宾物理地址。
 * @param {const slat::hook::entry_t* const} hook_entry Hook 条目。
 * @return {std::uint8_t} 是否清理成功。
 * @throws {无} 不抛出异常。
 * @example
 * const auto ok = clean_up_hook_ptes(gpa, entry);
 */
std::uint8_t clean_up_hook_ptes(slat::context_t* ctx, const virtual_address_t target_guest_physical_address, const slat::hook::entry_t* const hook_entry)
{
	// 业务说明：恢复 Hyper-V 与 Hook PTE 的原始状态。
	// 输入：目标地址/hook_entry；输出：PTE 还原结果；规则：PTE 缺失返回失败；异常：不抛出。
	slat_pte* const target_pte = slat::get_pte(slat::hyperv_cr3(ctx), target_guest_physical_address, ctx->heap_ctx);

	if (target_pte == nullptr)
	{
		return 0;
	}

	slat_pte* const hook_target_pte = slat::get_pte(slat::hook_cr3(ctx), target_guest_physical_address, ctx->heap_ctx);

	if (hook_target_pte == nullptr)
	{
		return 0;
	}

	// 业务说明：Intel 平台还原 PFN 与访问权限。
	// 输入：hook_entry；输出：PTE 权限恢复；规则：还原原始权限；异常：不抛出。
	target_pte->page_frame_number = hook_entry->original_pfn();

	target_pte->read_access = hook_entry->original_read_access();
	target_pte->write_access = hook_entry->original_write_access();
	target_pte->execute_access = hook_entry->original_execute_access();

	hook_target_pte->read_access = hook_entry->original_read_access();
	hook_target_pte->write_access = hook_entry->original_write_access();
	hook_target_pte->execute_access = hook_entry->original_execute_access();

	if (does_hook_need_merge(ctx, hook_entry, target_guest_physical_address) == 1)
	{
		// 业务说明：合并 4KB 页表回 2MB，提高性能。
		// 输入：目标地址；输出：页表合并；规则：两套 SLAT 均合并；异常：不抛出。
		slat::merge_4kb_pt(slat::hyperv_cr3(ctx), target_guest_physical_address, ctx->heap_ctx);
		slat::merge_4kb_pt(slat::hook_cr3(ctx), target_guest_physical_address, ctx->heap_ctx);
	}

	return 1;
}

/**
 * @description 将 Hook 条目从已用链表移回空闲链表。
 * @param {slat::context_t*} ctx SLAT 上下文。
 * @param {slat::hook::entry_t* const} hook_entry 目标条目。
 * @param {slat::hook::entry_t* const} previous_hook_entry 前驱条目。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * clean_up_hook_entry(entry, prev);
 */
void clean_up_hook_entry(slat::context_t* ctx, slat::hook::entry_t* const hook_entry, slat::hook::entry_t* const previous_hook_entry)
{
	// 业务说明：从已用链表摘除条目并放回空闲链表。
	// 输入：hook_entry/previous_hook_entry；输出：链表更新；规则：处理头节点与非头节点；异常：不抛出。
	if (previous_hook_entry == nullptr)
	{
		ctx->used_hook_list_head = hook_entry->next();
	}
	else
	{
		previous_hook_entry->set_next(hook_entry->next());
	}

	hook_entry->set_next(ctx->available_hook_list_head);

	ctx->available_hook_list_head = hook_entry;
}

/**
 * @description 移除指定来宾物理地址的 Hook。
 * @param {const virtual_address_t} guest_physical_address 目标来宾物理地址。
 * @return {std::uint64_t} 是否移除成功。
 * @throws {无} 不抛出异常。
 * @example
 * const auto ok = slat::hook::remove(gpa);
 */
std::uint64_t slat::hook::remove(slat::context_t* ctx, const virtual_address_t guest_physical_address)
{
	// 业务说明：加锁保证 Hook 删除过程线程安全。
	// 输入：目标地址；输出：删除结果；规则：不存在返回 0；异常：不抛出。
	ctx->hook_mutex.lock();

	entry_t* previous_hook_entry = nullptr;

	entry_t* const hook_entry = entry_t::find(ctx, guest_physical_address.address >> 12, &previous_hook_entry);

	if (hook_entry == nullptr)
	{
		ctx->hook_mutex.release();

		return 0;
	}

	// 业务说明：清理 PTE 并回收条目。
	// 输入：guest_physical_address/hook_entry；输出：清理结果；规则：先清理 PTE 后回收；异常：不抛出。
	const std::uint8_t pte_cleanup_status = clean_up_hook_ptes(ctx, guest_physical_address, hook_entry);

	clean_up_hook_entry(ctx, hook_entry, previous_hook_entry);

	ctx->hook_mutex.release();

	// 业务说明：仅刷新当前核心缓存，避免全核 NMI 导致超时。
	// 输入：无；输出：TLB/EPT 刷新；规则：仅当前核心；异常：不抛出。
	flush_current_logical_processor_cache();

	return pte_cleanup_status;
}
