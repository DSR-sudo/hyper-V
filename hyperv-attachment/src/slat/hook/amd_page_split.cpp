#include "amd_page_split.h"

#ifndef _INTELMACHINE
#include "../cr3/pte.h"

#include "../../structures/virtual_address.h"
#include "../../crt/crt.h"

/**
 * @description 设置目标页的可执行性。
 * @param {const cr3} slat_cr3 SLAT CR3。
 * @param {const virtual_address_t} target_guest_address 目标来宾物理地址。
 * @param {const std::uint8_t} execute_disable 是否禁用执行。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * set_page_executability(cr3_value, gpa, 1);
 */
static void set_page_executability(const cr3 slat_cr3, const virtual_address_t target_guest_address, const std::uint8_t execute_disable)
{
	// 业务说明：定位目标 PTE 并更新执行权限位。
	// 输入：slat_cr3/target_guest_address/execute_disable；输出：PTE 权限更新；规则：PTE 为空则忽略；异常：不抛出。
	slat_pte* const pte = slat::get_pte(slat_cr3, target_guest_address, 1);

	if (pte != nullptr)
	{
		pte->execute_disable = execute_disable;
	}
}

/**
 * @description 设置前一页的可执行性。
 * @param {const cr3} slat_cr3 SLAT CR3。
 * @param {const virtual_address_t} target_guest_address 目标来宾物理地址。
 * @param {const std::uint8_t} execute_disable 是否禁用执行。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * set_previous_page_executability(cr3_value, gpa, 0);
 */
static void set_previous_page_executability(const cr3 slat_cr3, const virtual_address_t target_guest_address, const std::uint8_t execute_disable)
{
	// 业务说明：计算前一页地址并调整执行权限。
	// 输入：target_guest_address；输出：前一页权限更新；规则：向前偏移 4KB；异常：不抛出。
	const virtual_address_t previous_page_address = { .address = target_guest_address.address - 0x1000 };

	set_page_executability(slat_cr3, previous_page_address, execute_disable);
}

/**
 * @description 设置后一页的可执行性。
 * @param {const cr3} slat_cr3 SLAT CR3。
 * @param {const virtual_address_t} target_guest_address 目标来宾物理地址。
 * @param {const std::uint8_t} execute_disable 是否禁用执行。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * set_next_page_executability(cr3_value, gpa, 0);
 */
static void set_next_page_executability(const cr3 slat_cr3, const virtual_address_t target_guest_address, const std::uint8_t execute_disable)
{
	// 业务说明：计算后一页地址并调整执行权限。
	// 输入：target_guest_address；输出：后一页权限更新；规则：向后偏移 4KB；异常：不抛出。
	const virtual_address_t next_page_address = { .address = target_guest_address.address + 0x1000 };

	set_page_executability(slat_cr3, next_page_address, execute_disable);
}

/**
 * @description 修复跨页指令的执行权限。
 * @param {const cr3} slat_cr3 SLAT CR3。
 * @param {const virtual_address_t} target_guest_address 目标来宾物理地址。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * slat::hook::fix_split_instructions(cr3_value, gpa);
 */
void slat::hook::fix_split_instructions(const cr3 slat_cr3, const virtual_address_t target_guest_address)
{
	// 业务说明：允许相邻页执行以修复跨页指令。
	// 输入：target_guest_address；输出：相邻页执行权限打开；规则：前后页均设置；异常：不抛出。
	set_previous_page_executability(slat_cr3, target_guest_address, 0);
	set_next_page_executability(slat_cr3, target_guest_address, 0);
}

/**
 * @description 恢复跨页指令的执行权限设置。
 * @param {const entry_t* const} hook_entry 当前 Hook 条目。
 * @param {const cr3} slat_cr3 SLAT CR3。
 * @param {const virtual_address_t} target_guest_address 目标来宾物理地址。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * slat::hook::unfix_split_instructions(entry, cr3_value, gpa);
 */
void slat::hook::unfix_split_instructions(const entry_t* const hook_entry, const cr3 slat_cr3, const virtual_address_t target_guest_address)
{
	// 业务说明：根据附近 Hook 情况恢复前后页执行权限。
	// 输入：hook_entry/target_guest_address；输出：权限恢复；规则：就近 Hook 决定恢复策略；异常：不抛出。
	const entry_t* const other_hook_entry_in_range = entry_t::find_closest_in_2mb_range(target_guest_address.address >> 12, hook_entry);

	if (other_hook_entry_in_range != nullptr)
	{
		const std::int64_t source_pfn = static_cast<std::int64_t>(hook_entry->original_pfn());
		const std::int64_t other_pfn = static_cast<std::int64_t>(other_hook_entry_in_range->original_pfn());

		const std::int64_t pfn_difference = source_pfn - other_pfn;
		const std::int64_t abs_pfn_difference = crt::abs(pfn_difference);

		const std::uint8_t is_page_nearby = abs_pfn_difference <= 2;

		std::uint8_t has_fixed = 1;

		if (is_page_nearby == 1 && 0 < pfn_difference)
		{
			// 业务说明：附近 Hook 位于前页时，关闭后页执行权限。
			// 输入：pfn_difference；输出：后页权限更新；规则：差值为正；异常：不抛出。
			set_next_page_executability(slat_cr3, target_guest_address, 1);

			has_fixed = 1;
		}
		else if (is_page_nearby == 1) // negative pfn difference
		{
			// 业务说明：附近 Hook 位于后页时，关闭前页执行权限。
			// 输入：pfn_difference；输出：前页权限更新；规则：差值为负；异常：不抛出。
			set_previous_page_executability(slat_cr3, target_guest_address, 1);

			has_fixed = 1;
		}

		if (abs_pfn_difference == 1)
		{
			// 业务说明：相邻页仅差 1 时，确保当前页可执行。
			// 输入：abs_pfn_difference；输出：当前页执行权限打开；规则：差值为 1；异常：不抛出。
			set_page_executability(slat_cr3, target_guest_address, 0);
		}

		if (has_fixed == 1)
		{
			return;
		}
	}

	// 业务说明：范围内无附近 Hook，保持前后页可执行以避免跨页问题。
	// 输入：无；输出：相邻页权限更新；规则：开启执行；异常：不抛出。
	set_previous_page_executability(slat_cr3, target_guest_address, 0);
	set_next_page_executability(slat_cr3, target_guest_address, 0);
}
#endif
