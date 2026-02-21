#include "pte.h"

#include "../../memory_manager/memory_manager.h"
#include "../../memory_manager/heap_manager.h"
#include "../../logs/logs.h"
#include "../../../runtime/runtime_context.h"

#include "../../structures/virtual_address.h"

/**
 * @description 获取 SLAT PML4 表项。
 * @param {const cr3} slat_cr3 SLAT CR3（通常为 EPT 指针）。
 * @param {const virtual_address_t} guest_physical_address 来宾物理地址。
 * @return {slat_pml4e*} 指向 SLAT PML4 表项的指针。
 * @throws {无} 不抛出异常。
 * @example
 * auto* pml4e = slat::get_pml4e(slat_cr3, gpa);
 */
slat_pml4e* slat::get_pml4e(const cr3 slat_cr3, const virtual_address_t guest_physical_address)
{
	// 业务说明：根据 SLAT CR3 获取 PML4 表基址，并根据 GPA 的 PML4 索引定位表项。
	// 输入：slat_cr3/gpa；输出：PML4E 指针；规则：直接索引；异常：不抛出。
	const auto pml4 = static_cast<slat_pml4e*>(memory_manager::map_host_physical(slat_cr3.address_of_page_directory << 12));

	return &pml4[guest_physical_address.pml4_idx];
}

/**
 * @description 获取 SLAT PDPTE 表项。
 * @param {const slat_pml4e* const} pml4e 上一级 PML4 表项。
 * @param {const virtual_address_t} guest_physical_address 来宾物理地址。
 * @return {slat_pdpte*} 指向 SLAT PDPTE 表项的指针。
 * @throws {无} 不抛出异常。
 * @example
 * auto* pdpte = slat::get_pdpte(pml4e, gpa);
 */
slat_pdpte* slat::get_pdpte(const slat_pml4e* const pml4e, const virtual_address_t guest_physical_address)
{
	// 业务说明：从 PML4E 获取 PDPT 物理页号，映射为虚拟地址，并根据 GPA 的 PDPT 索引定位表项。
	// 输入：pml4e/gpa；输出：PDPTE 指针；规则：页号转换；异常：不抛出。
	const auto pdpt = static_cast<slat_pdpte*>(memory_manager::map_host_physical(pml4e->page_frame_number << 12));

	return &pdpt[guest_physical_address.pdpt_idx];
}

/**
 * @description 获取 SLAT PDE 表项。
 * @param {const slat_pdpte* const} pdpte 上一级 PDPTE 表项。
 * @param {const virtual_address_t} guest_physical_address 来宾物理地址。
 * @return {slat_pde*} 指向 SLAT PDE 表项的指针。
 * @throws {无} 不抛出异常。
 * @example
 * auto* pde = slat::get_pde(pdpte, gpa);
 */
slat_pde* slat::get_pde(const slat_pdpte* const pdpte, const virtual_address_t guest_physical_address)
{
	// 业务说明：从 PDPTE 获取 PD 物理页号，映射为虚拟地址，并根据 GPA 的 PD 索引定位表项。
	// 输入：pdpte/gpa；输出：PDE 指针；规则：页号转换；异常：不抛出。
	const auto pd = static_cast<slat_pde*>(memory_manager::map_host_physical(pdpte->page_frame_number << 12));

	return &pd[guest_physical_address.pd_idx];
}

/**
 * @description 获取 SLAT PTE 表项。
 * @param {const slat_pde* const} pde 上一级 PDE 表项。
 * @param {const virtual_address_t} guest_physical_address 来宾物理地址。
 * @return {slat_pte*} 指向 SLAT PTE 表项的指针。
 * @throws {无} 不抛出异常。
 * @example
 * auto* pte = slat::get_pte(pde, gpa);
 */
slat_pte* slat::get_pte(const slat_pde* const pde, const virtual_address_t guest_physical_address)
{
	// 业务说明：从 PDE 获取 PT 物理页号，映射为虚拟地址，并根据 GPA 的 PT 索引定位表项。
	// 输入：pde/gpa；输出：PTE 指针；规则：页号转换；异常：不抛出。
	const auto pt = static_cast<slat_pte*>(memory_manager::map_host_physical(pde->page_frame_number << 12));

	return &pt[guest_physical_address.pt_idx];
}

/**
 * @description 获取 SLAT PDE 表项（支持大页拆分）。
 * @param {const cr3} slat_cr3 SLAT CR3。
 * @param {const virtual_address_t} guest_physical_address 来宾物理地址。
 * @param {heap_manager::context_t*} heap_ctx 堆管理上下文。
 * @param {const std::uint8_t} force_split_pages 是否强制拆分大页。
 * @return {slat_pde*} 指向 SLAT PDE 表项的指针，失败返回 nullptr。
 * @throws {无} 不抛出异常。
 * @example
 * auto* pde = slat::get_pde(slat_cr3, gpa, ctx, 1);
 */
slat_pde* slat::get_pde(const cr3 slat_cr3, const virtual_address_t guest_physical_address,
	heap_manager::context_t* heap_ctx, const std::uint8_t force_split_pages)
{
	// 业务说明：逐级获取 PML4E -> PDPTE -> PDE。如果遇到 1GB 大页且允许拆分，则调用拆分逻辑。
	// 输入：slat_cr3/gpa/heap_ctx/force_split；输出：PDE 指针；规则：大页必须拆分才能获取下一级；异常：不抛出。
	const slat_pml4e* const pml4e = get_pml4e(slat_cr3, guest_physical_address);

	if (pml4e == nullptr)
	{
		return nullptr;
	}

	slat_pdpte* const pdpte = get_pdpte(pml4e, guest_physical_address);

	if (pdpte == nullptr)
	{
		return nullptr;
	}

	const auto large_pdpte = reinterpret_cast<slat_pdpte_1gb*>(pdpte);

	if (large_pdpte->large_page == 1 && (force_split_pages == 0 || split_1gb_pdpte(large_pdpte, heap_ctx) == 0))
	{
		return nullptr;
	}

	return get_pde(pdpte, guest_physical_address);
}

/**
 * @description 获取 SLAT PTE 表项（支持大页拆分）。
 * @param {const cr3} slat_cr3 SLAT CR3。
 * @param {const virtual_address_t} guest_physical_address 来宾物理地址。
 * @param {heap_manager::context_t*} heap_ctx 堆管理上下文。
 * @param {const std::uint8_t} force_split_pages 是否强制拆分大页。
 * @param {std::uint8_t* const} paging_split_state 可选输出拆分状态（1 表示发生了拆分）。
 * @return {slat_pte*} 指向 SLAT PTE 表项的指针，失败返回 nullptr。
 * @throws {无} 不抛出异常。
 * @example
 * auto* pte = slat::get_pte(slat_cr3, gpa, ctx, 1, &split_state);
 */
slat_pte* slat::get_pte(const cr3 slat_cr3, const virtual_address_t guest_physical_address,
	heap_manager::context_t* heap_ctx, const std::uint8_t force_split_pages, std::uint8_t* const paging_split_state)
{
	// 业务说明：先获取 PDE，如果 PDE 指向 2MB 大页且允许拆分，则将其拆分为 4KB 页表，再获取 PTE。
	// 输入：slat_cr3/gpa/heap_ctx/force_split；输出：PTE 指针；规则：确保操作的是 4KB 粒度；异常：不抛出。
	slat_pde* const pde = get_pde(slat_cr3, guest_physical_address, heap_ctx, force_split_pages);

	if (pde == nullptr)
	{
		return nullptr;
	}

	const auto large_pde = reinterpret_cast<slat_pde_2mb*>(pde);

	if (large_pde->large_page == 1)
	{
		if (force_split_pages == 0 || split_2mb_pde(large_pde, heap_ctx) == 0)
		{
			logs::print(&g_runtime_context.log_ctx, "[SLAT] Split2M failed GPA=0x%p\n", guest_physical_address.address);
			return nullptr;
		}

		if (paging_split_state != nullptr)
		{
			*paging_split_state = 1;
		}
	}

	return get_pte(pde, guest_physical_address);
}

/**
 * @description 拆分 2MB 大页为 512 个 4KB 小页。
 * @param {slat_pde_2mb* const} large_pde 指向 2MB 大页 PDE 的指针。
 * @param {heap_manager::context_t*} heap_ctx 堆管理上下文。
 * @return {std::uint8_t} 成功返回 1，失败返回 0。
 * @throws {无} 不抛出异常。
 * @example
 * slat::split_2mb_pde(large_pde, ctx);
 */
std::uint8_t slat::split_2mb_pde(slat_pde_2mb* const large_pde, heap_manager::context_t* heap_ctx)
{
	// 业务说明：分配一个新的 4KB 页表，初始化 512 个 PTE，使其映射原 2MB 区域，然后更新 PDE 指向新页表。
	// 输入：large_pde/heap_ctx；输出：成功标志；规则：保持原有权限属性不变；异常：不抛出。
	const auto pt = static_cast<slat_pte*>(heap_manager::allocate_page(heap_ctx));

	if (pt == nullptr)
	{
		return 0;
	}

	for (std::uint64_t i = 0; i < 512; i++)
	{
		slat_pte* pte = &pt[i];

		pte->flags = 0;

#ifdef _INTELMACHINE
		pte->execute_access = large_pde->execute_access;
		pte->read_access = large_pde->read_access;
		pte->write_access = large_pde->write_access;
		pte->memory_type = large_pde->memory_type;
		pte->ignore_pat = large_pde->ignore_pat;
		pte->user_mode_execute = large_pde->user_mode_execute;
		pte->verify_guest_paging = large_pde->verify_guest_paging;
		pte->paging_write_access = large_pde->paging_write_access;
		pte->supervisor_shadow_stack = large_pde->supervisor_shadow_stack;
		pte->suppress_ve = large_pde->suppress_ve;
#else
		pte->execute_disable = large_pde->execute_disable;
		pte->present = large_pde->present;
		pte->write = large_pde->write;
		pte->global = large_pde->global;
		pte->pat = large_pde->pat;
		pte->protection_key = large_pde->protection_key;
		pte->page_level_write_through = large_pde->page_level_write_through;
		pte->page_level_cache_disable = large_pde->page_level_cache_disable;
		pte->supervisor = large_pde->supervisor;
#endif

		pte->accessed = large_pde->accessed;
		pte->dirty = large_pde->dirty;

		pte->page_frame_number = (large_pde->page_frame_number << 9) + i;
	}

	const std::uint64_t pt_physical_address = memory_manager::unmap_host_physical(pt);

	slat_pde new_pde = { };

	new_pde.page_frame_number = pt_physical_address >> 12;

#ifdef _INTELMACHINE
	new_pde.read_access = 1;
	new_pde.write_access = 1;
	new_pde.execute_access = 1;
	new_pde.user_mode_execute = 1;
#else
	new_pde.present = 1;
	new_pde.write = 1;
	new_pde.supervisor = 1;
#endif

	large_pde->flags = new_pde.flags;

	return 1;
}

/**
 * @description 拆分 1GB 大页为 512 个 2MB 大页。
 * @param {slat_pdpte_1gb* const} large_pdpte 指向 1GB 大页 PDPTE 的指针。
 * @param {heap_manager::context_t*} heap_ctx 堆管理上下文。
 * @return {std::uint8_t} 成功返回 1，失败返回 0。
 * @throws {无} 不抛出异常。
 * @example
 * slat::split_1gb_pdpte(large_pdpte, ctx);
 */
std::uint8_t slat::split_1gb_pdpte(slat_pdpte_1gb* const large_pdpte, heap_manager::context_t* heap_ctx)
{
	// 业务说明：分配一个新的页目录（PD），初始化 512 个 2MB PDE，使其映射原 1GB 区域，然后更新 PDPTE 指向新页目录。
	// 输入：large_pdpte/heap_ctx；输出：成功标志；规则：保持原有权限属性不变；异常：不抛出。
	const auto pd = static_cast<slat_pde_2mb*>(heap_manager::allocate_page(heap_ctx));

	if (pd == nullptr)
	{
		return 0;
	}

	for (std::uint64_t i = 0; i < 512; i++)
	{
		slat_pde_2mb* pde = &pd[i];

		pde->flags = 0;

#ifdef _INTELMACHINE
		pde->execute_access = large_pdpte->execute_access;
		pde->read_access = large_pdpte->read_access;
		pde->write_access = large_pdpte->write_access;
		pde->memory_type = large_pdpte->memory_type;
		pde->ignore_pat = large_pdpte->ignore_pat;
		pde->user_mode_execute = large_pdpte->user_mode_execute;
		pde->verify_guest_paging = large_pdpte->verify_guest_paging;
		pde->paging_write_access = large_pdpte->paging_write_access;
		pde->supervisor_shadow_stack = large_pdpte->supervisor_shadow_stack;
		pde->suppress_ve = large_pdpte->suppress_ve;
#else
		pde->execute_disable = large_pdpte->execute_disable;
		pde->present = large_pdpte->present;
		pde->write = large_pdpte->write;
		pde->global = large_pdpte->global;
		pde->pat = large_pdpte->pat;
		pde->protection_key = large_pdpte->protection_key;
		pde->page_level_write_through = large_pdpte->page_level_write_through;
		pde->page_level_cache_disable = large_pdpte->page_level_cache_disable;
		pde->supervisor = large_pdpte->supervisor;
#endif

		pde->accessed = large_pdpte->accessed;
		pde->dirty = large_pdpte->dirty;

		pde->page_frame_number = (large_pdpte->page_frame_number << 9) + i;
		pde->large_page = 1;
	}

	const std::uint64_t pd_physical_address = memory_manager::unmap_host_physical(pd);

	slat_pdpte new_pdpte = { .flags = 0 };

	new_pdpte.page_frame_number = pd_physical_address >> 12;

#ifdef _INTELMACHINE
	new_pdpte.read_access = 1;
	new_pdpte.write_access = 1;
	new_pdpte.execute_access = 1;
	new_pdpte.user_mode_execute = 1;
#else
	new_pdpte.present = 1;
	new_pdpte.write = 1;
	new_pdpte.supervisor = 1;
#endif

	large_pdpte->flags = new_pdpte.flags;

	return 1;
}

/**
 * @description 合并 4KB 小页为 2MB 大页。
 * @param {const cr3} slat_cr3 SLAT CR3。
 * @param {const virtual_address_t} guest_physical_address 来宾物理地址。
 * @param {heap_manager::context_t*} heap_ctx 堆管理上下文。
 * @return {std::uint8_t} 成功返回 1，失败返回 0。
 * @throws {无} 不抛出异常。
 * @example
 * slat::merge_4kb_pt(slat_cr3, gpa, ctx);
 */
std::uint8_t slat::merge_4kb_pt(const cr3 slat_cr3, const virtual_address_t guest_physical_address, heap_manager::context_t* heap_ctx)
{
	// 业务说明：将之前拆分的 4KB 页表合并回 2MB 大页，释放占用的页表内存。通常用于 Hook 卸载。
	// 输入：slat_cr3/gpa/heap_ctx；输出：成功标志；规则：合并后还原大页属性；异常：不抛出。
	slat_pde* const pde = get_pde(slat_cr3, guest_physical_address, heap_ctx);

	if (pde == nullptr)
	{
		return 0;
	}

	const auto large_pde = reinterpret_cast<slat_pde_2mb*>(pde);

	if (large_pde->large_page == 1)
	{
		return 1;
	}

	const std::uint64_t pt_physical_address = pde->page_frame_number << 12;

	slat_pte* const pte = get_pte(pde, guest_physical_address);

	slat_pde_2mb new_large_pde = { };

#ifdef _INTELMACHINE
	new_large_pde.execute_access = pte->execute_access;
	new_large_pde.read_access = pte->read_access;
	new_large_pde.write_access = pte->write_access;
	new_large_pde.memory_type = pte->memory_type;
	new_large_pde.ignore_pat = pte->ignore_pat;
	new_large_pde.user_mode_execute = pte->user_mode_execute;
	new_large_pde.verify_guest_paging = pte->verify_guest_paging;
	new_large_pde.paging_write_access = pte->paging_write_access;
	new_large_pde.supervisor_shadow_stack = pte->supervisor_shadow_stack;
	new_large_pde.suppress_ve = pte->suppress_ve;
#else
		new_large_pde.execute_disable = pte->execute_disable;
		new_large_pde.present = pte->present;
		new_large_pde.write = pte->write;
		new_large_pde.global = pte->global;
		new_large_pde.pat = pte->pat;
		new_large_pde.protection_key = pte->protection_key;
		new_large_pde.page_level_write_through = pte->page_level_write_through;
		new_large_pde.page_level_cache_disable = pte->page_level_cache_disable;
		new_large_pde.supervisor = pte->supervisor;
#endif

	new_large_pde.page_frame_number = pte->page_frame_number >> 9;
	new_large_pde.large_page = 1;

	*large_pde = new_large_pde;

	void* const pt_allocation_mapped = memory_manager::map_host_physical(pt_physical_address);

	heap_manager::free_page(heap_ctx, pt_allocation_mapped);

	return 1;
}

/**
 * @description 检查 PTE 是否存在（Present/Read Access）。
 * @param {const void* const} pte_in PTE 指针。
 * @return {std::uint8_t} 存在返回 1，否则返回 0。
 * @throws {无} 不抛出异常。
 * @example
 * auto exists = slat::is_pte_present(pte);
 */
std::uint8_t slat::is_pte_present(const void* const pte_in)
{
	// 业务说明：根据 CPU 架构检查 PTE 的有效位（Intel 为 Read Access，AMD 为 Present）。
	// 输入：pte_in；输出：是否有效；规则：空指针返回 0；异常：不抛出。
	if (!pte_in)
	{
		return 0;
	}

	const auto pte = static_cast<const slat_pte*>(pte_in);

#ifdef _INTELMACHINE
	return pte->read_access == 1;
#else
		return pte->present == 1;
#endif
}

/**
 * @description 检查 PTE 是否为大页。
 * @param {const void* const} pte_in PTE 指针。
 * @return {std::uint8_t} 是大页返回 1，否则返回 0。
 * @throws {无} 不抛出异常。
 * @example
 * auto is_large = slat::is_pte_large(pte);
 */
std::uint8_t slat::is_pte_large(const void* const pte_in)
{
	// 业务说明：检查 PTE 的大页标志位。
	// 输入：pte_in；输出：是否大页；规则：空指针返回 0；异常：不抛出。
	if (!pte_in)
	{
		return 0;
	}

	const auto large_pte = static_cast<const slat_pde_2mb*>(pte_in);

	return large_pte->large_page;
}
