#include "pte.h"

#include "../../memory_manager/memory_manager.h"
#include "../../memory_manager/heap_manager.h"

#include "../../structures/virtual_address.h"

slat_pml4e* slat::get_pml4e(const cr3 slat_cr3, const virtual_address_t guest_physical_address)
{
	const auto pml4 = static_cast<slat_pml4e*>(memory_manager::map_host_physical(slat_cr3.address_of_page_directory << 12));

	return &pml4[guest_physical_address.pml4_idx];
}

slat_pdpte* slat::get_pdpte(const slat_pml4e* const pml4e, const virtual_address_t guest_physical_address)
{
	const auto pdpt = static_cast<slat_pdpte*>(memory_manager::map_host_physical(pml4e->page_frame_number << 12));

	return &pdpt[guest_physical_address.pdpt_idx];
}

slat_pde* slat::get_pde(const slat_pdpte* const pdpte, const virtual_address_t guest_physical_address)
{
	const auto pd = static_cast<slat_pde*>(memory_manager::map_host_physical(pdpte->page_frame_number << 12));

	return &pd[guest_physical_address.pd_idx];
}

slat_pte* slat::get_pte(const slat_pde* const pde, const virtual_address_t guest_physical_address)
{
	const auto pt = static_cast<slat_pte*>(memory_manager::map_host_physical(pde->page_frame_number << 12));

	return &pt[guest_physical_address.pt_idx];
}

slat_pde* slat::get_pde(const cr3 slat_cr3, const virtual_address_t guest_physical_address,
	heap_manager::context_t* heap_ctx, const std::uint8_t force_split_pages)
{
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

slat_pte* slat::get_pte(const cr3 slat_cr3, const virtual_address_t guest_physical_address,
	heap_manager::context_t* heap_ctx, const std::uint8_t force_split_pages, std::uint8_t* const paging_split_state)
{
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
			return nullptr;
		}

		if (paging_split_state != nullptr)
		{
			*paging_split_state = 1;
		}
	}

	return get_pte(pde, guest_physical_address);
}

std::uint8_t slat::split_2mb_pde(slat_pde_2mb* const large_pde, heap_manager::context_t* heap_ctx)
{
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

std::uint8_t slat::split_1gb_pdpte(slat_pdpte_1gb* const large_pdpte, heap_manager::context_t* heap_ctx)
{
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

std::uint8_t slat::merge_4kb_pt(const cr3 slat_cr3, const virtual_address_t guest_physical_address, heap_manager::context_t* heap_ctx)
{
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

std::uint8_t slat::is_pte_present(const void* const pte_in)
{
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

std::uint8_t slat::is_pte_large(const void* const pte_in)
{
	if (!pte_in)
	{
		return 0;
	}

	const auto large_pte = static_cast<const slat_pde_2mb*>(pte_in);

	return large_pte->large_page;
}
