#include "hook_entry.h"
#include "../slat.h"
#include "../../crt/crt.h"

/**
 * @description 获取链表中的下一个 Hook 条目。
 * @param {void} 无。
 * @return {entry_t*} 下一条目指针。
 * @throws {无} 不抛出异常。
 * @example
 * auto next_entry = entry.next();
 */
slat::hook::entry_t* slat::hook::entry_t::next() const
{
	// 业务说明：将内部保存的指针转换为条目类型。
	// 输入：无；输出：下一条目；规则：直接返回内部指针；异常：不抛出。
	return reinterpret_cast<entry_t*>(next_);
}

/**
 * @description 设置链表中的下一个 Hook 条目。
 * @param {entry_t* const} next_entry 下一条目指针。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * entry.set_next(next);
 */
void slat::hook::entry_t::set_next(entry_t* const next_entry)
{
	// 业务说明：保存下一条目的指针地址。
	// 输入：next_entry；输出：next_ 更新；规则：指针转整数保存；异常：不抛出。
	next_ = reinterpret_cast<std::uint64_t>(next_entry);
}

/**
 * @description 获取原始页帧号。
 * @param {void} 无。
 * @return {std::uint64_t} 原始页帧号。
 * @throws {无} 不抛出异常。
 * @example
 * const auto pfn = entry.original_pfn();
 */
std::uint64_t slat::hook::entry_t::original_pfn() const
{
	// 业务说明：返回条目保存的原始 PFN。
	// 输入：无；输出：original_pfn_；规则：直接返回；异常：不抛出。
	return original_pfn_;
}

/**
 * @description 设置原始页帧号。
 * @param {const std::uint64_t} original_pfn 原始 PFN。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * entry.set_original_pfn(pfn);
 */
void slat::hook::entry_t::set_original_pfn(const std::uint64_t original_pfn)
{
	// 业务说明：更新条目的原始 PFN。
	// 输入：original_pfn；输出：original_pfn_ 更新；规则：直接赋值；异常：不抛出。
	original_pfn_ = original_pfn;
}

/**
 * @description 获取原始读访问标志。
 * @param {void} 无。
 * @return {std::uint64_t} 原始读访问标志。
 * @throws {无} 不抛出异常。
 * @example
 * const auto flag = entry.original_read_access();
 */
std::uint64_t slat::hook::entry_t::original_read_access() const
{
	// 业务说明：返回条目保存的原始读权限。
	// 输入：无；输出：original_read_access_；规则：直接返回；异常：不抛出。
	return original_read_access_;
}

/**
 * @description 获取原始写访问标志。
 * @param {void} 无。
 * @return {std::uint64_t} 原始写访问标志。
 * @throws {无} 不抛出异常。
 * @example
 * const auto flag = entry.original_write_access();
 */
std::uint64_t slat::hook::entry_t::original_write_access() const
{
	// 业务说明：返回条目保存的原始写权限。
	// 输入：无；输出：original_write_access_；规则：直接返回；异常：不抛出。
	return original_write_access_;
}

/**
 * @description 获取原始执行访问标志。
 * @param {void} 无。
 * @return {std::uint64_t} 原始执行访问标志。
 * @throws {无} 不抛出异常。
 * @example
 * const auto flag = entry.original_execute_access();
 */
std::uint64_t slat::hook::entry_t::original_execute_access() const
{
	// 业务说明：返回条目保存的原始执行权限。
	// 输入：无；输出：original_execute_access_；规则：直接返回；异常：不抛出。
	return original_execute_access_;
}

/**
 * @description 获取分页拆分页状态。
 * @param {void} 无。
 * @return {std::uint64_t} 分页拆分页状态。
 * @throws {无} 不抛出异常。
 * @example
 * const auto state = entry.paging_split_state();
 */
std::uint64_t slat::hook::entry_t::paging_split_state() const
{
	// 业务说明：返回条目保存的拆分页状态。
	// 输入：无；输出：paging_split_state_；规则：直接返回；异常：不抛出。
	return paging_split_state_;
}

/**
 * @description 设置原始读访问标志。
 * @param {const std::uint64_t} original_read_access 原始读权限。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * entry.set_original_read_access(flag);
 */
void slat::hook::entry_t::set_original_read_access(const std::uint64_t original_read_access)
{
	// 业务说明：更新条目的原始读权限。
	// 输入：original_read_access；输出：original_read_access_ 更新；规则：直接赋值；异常：不抛出。
	original_read_access_ = original_read_access;
}

/**
 * @description 设置原始写访问标志。
 * @param {const std::uint64_t} original_write_access 原始写权限。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * entry.set_original_write_access(flag);
 */
void slat::hook::entry_t::set_original_write_access(const std::uint64_t original_write_access)
{
	// 业务说明：更新条目的原始写权限。
	// 输入：original_write_access；输出：original_write_access_ 更新；规则：直接赋值；异常：不抛出。
	original_write_access_ = original_write_access;
}

/**
 * @description 设置原始执行访问标志。
 * @param {const std::uint64_t} original_execute_access 原始执行权限。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * entry.set_original_execute_access(flag);
 */
void slat::hook::entry_t::set_original_execute_access(const std::uint64_t original_execute_access)
{
	// 业务说明：更新条目的原始执行权限。
	// 输入：original_execute_access；输出：original_execute_access_ 更新；规则：直接赋值；异常：不抛出。
	original_execute_access_ = original_execute_access;
}

/**
 * @description 设置分页拆分页状态。
 * @param {const std::uint64_t} paging_split_state 拆分页状态。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * entry.set_paging_split_state(state);
 */
void slat::hook::entry_t::set_paging_split_state(const std::uint64_t paging_split_state)
{
	// 业务说明：更新条目的拆分页状态。
	// 输入：paging_split_state；输出：paging_split_state_ 更新；规则：直接赋值；异常：不抛出。
	paging_split_state_ = paging_split_state;
}

/**
 * @description 在已使用列表中查找指定 PFN 的 Hook 条目。
 * @param {slat::context_t*} ctx SLAT 上下文。
 * @param {const std::uint64_t} target_original_4kb_pfn 目标 4KB PFN。
 * @param {entry_t** const} previous_entry_out 可选输出前驱条目。
 * @return {entry_t*} 找到的条目指针，失败返回 nullptr。
 * @throws {无} 不抛出异常。
 * @example
 * auto entry = entry_t::find(ctx, pfn, &prev);
 */
slat::hook::entry_t* slat::hook::entry_t::find(slat::context_t* ctx, const std::uint64_t target_original_4kb_pfn, entry_t** const previous_entry_out)
{
	// 业务说明：遍历使用链表，定位匹配 PFN 的条目。
	// 输入：target_original_4kb_pfn；输出：条目与前驱；规则：找不到返回 nullptr；异常：不抛出。
	entry_t* current_entry = ctx->used_hook_list_head;
	entry_t* previous_entry = nullptr;

	while (current_entry != nullptr)
	{
		if (current_entry->original_pfn() == target_original_4kb_pfn)
		{
			if (previous_entry_out != nullptr)
			{
				*previous_entry_out = previous_entry;
			}

			return current_entry;
		}

		previous_entry = current_entry;
		current_entry = current_entry->next();
	}

	return nullptr;
}

/**
 * @description 在同一 2MB 范围内查找 Hook 条目。
 * @param {slat::context_t*} ctx SLAT 上下文。
 * @param {const std::uint64_t} target_original_4kb_pfn 目标 4KB PFN。
 * @param {const entry_t* const} excluding_hook 需要排除的条目。
 * @return {entry_t*} 找到的条目指针，失败返回 nullptr。
 * @throws {无} 不抛出异常。
 * @example
 * auto entry = entry_t::find_in_2mb_range(ctx, pfn, excluding);
 */
slat::hook::entry_t* slat::hook::entry_t::find_in_2mb_range(slat::context_t* ctx, const std::uint64_t target_original_4kb_pfn, const entry_t* const excluding_hook)
{
	// 业务说明：按 2MB PFN 范围匹配，忽略指定条目。
	// 输入：target_original_4kb_pfn/excluding_hook；输出：匹配条目；规则：PFN 匹配即返回；异常：不抛出。
	entry_t* current_entry = ctx->used_hook_list_head;

	const std::uint64_t target_2mb_pfn = target_original_4kb_pfn >> 9;

	while (current_entry != nullptr)
	{
		const std::uint64_t current_hook_2mb_pfn = current_entry->original_pfn() >> 9;

		if (excluding_hook != current_entry && current_hook_2mb_pfn == target_2mb_pfn)
		{
			return current_entry;
		}

		current_entry = current_entry->next();
	}

	return nullptr;
}

/**
 * @description 在 2MB 范围内查找距离最近的 Hook 条目。
 * @param {slat::context_t*} ctx SLAT 上下文。
 * @param {const std::uint64_t} target_original_4kb_pfn 目标 4KB PFN。
 * @param {const entry_t* const} excluding_hook 需要排除的条目。
 * @return {entry_t*} 最近的条目，失败返回 nullptr。
 * @throws {无} 不抛出异常。
 * @example
 * auto entry = entry_t::find_closest_in_2mb_range(ctx, pfn, excluding);
 */
slat::hook::entry_t* slat::hook::entry_t::find_closest_in_2mb_range(slat::context_t* ctx, const std::uint64_t target_original_4kb_pfn, const entry_t* const excluding_hook)
{
	// 业务说明：扫描 2MB 范围内条目并选择 PFN 距离最小者。
	// 输入：target_original_4kb_pfn/excluding_hook；输出：最近条目；规则：差值最小者；异常：不抛出。
	entry_t* current_entry = ctx->used_hook_list_head;

	const std::uint64_t target_2mb_pfn = target_original_4kb_pfn >> 9;

	entry_t* closest_entry = nullptr;
	std::int64_t closest_difference = INT64_MAX;

	while (current_entry != nullptr)
	{
		const std::uint64_t current_hook_4kb_pfn = current_entry->original_pfn();
		const std::uint64_t current_hook_2mb_pfn = current_hook_4kb_pfn >> 9;

		if (excluding_hook != current_entry && current_hook_2mb_pfn == target_2mb_pfn)
		{
			const std::int64_t current_difference = crt::abs(static_cast<std::int64_t>(current_hook_4kb_pfn) - static_cast<std::int64_t>(target_original_4kb_pfn));

			if (current_difference < closest_difference)
			{
				closest_difference = current_difference;
				closest_entry = current_entry;
			}
		}

		current_entry = current_entry->next();
	}

	return closest_entry;
}
