#include "deep_copy.h"
#include "pte.h"

#include "../../memory_manager/memory_manager.h"
#include "../../memory_manager/heap_manager.h"

void make_pt_copy(const slat_pte* const hyperv_pt, slat_pte* const hook_pt, const std::uint8_t make_non_executable)
{
	for (std::uint64_t pt_index = 0; pt_index < 512; pt_index++)
	{
		const slat_pte* const hyperv_pte = &hyperv_pt[pt_index];
		slat_pte* const hook_pte = &hook_pt[pt_index];

		hook_pte->flags = hyperv_pte->flags;

		if (make_non_executable)
		{
#ifdef _INTELMACHINE
			hook_pte->execute_access = 0;
#else
			hook_pte->execute_disable = 1;
#endif
		}
	}
}

void make_pd_copy(const slat_pde* const hyperv_pd, slat_pde* const hook_pd, heap_manager::context_t* heap_ctx, const std::uint8_t make_non_executable)
{
	for (std::uint64_t pd_index = 0; pd_index < 512; pd_index++)
	{
		const slat_pde* const hyperv_pde = &hyperv_pd[pd_index];
		slat_pde* const hook_pde = &hook_pd[pd_index];

		hook_pde->flags = hyperv_pde->flags;

		if (slat::is_pte_present(hyperv_pde) == 0)
		{
			continue;
		}

		if (slat::is_pte_large(hyperv_pde) == 0)
		{
			const slat_pte* const hyperv_pt = slat::get_pte(hyperv_pde, { });
			const auto hook_pt = static_cast<slat_pte*>(heap_manager::allocate_page(heap_ctx));

			hook_pde->page_frame_number = memory_manager::unmap_host_physical(hook_pt) >> 12;

			make_pt_copy(hyperv_pt, hook_pt, make_non_executable);
		}
		else if (make_non_executable)
		{
#ifdef _INTELMACHINE
			hook_pde->execute_access = 0;
#else
			hook_pde->execute_disable = 1;
#endif
		}
	}
}

void make_pdpt_copy(const slat_pdpte* const hyperv_pdpt, slat_pdpte* const hook_pdpt, heap_manager::context_t* heap_ctx, const std::uint8_t make_non_executable)
{
	for (std::uint64_t pdpt_index = 0; pdpt_index < 512; pdpt_index++)
	{
		const slat_pdpte* const hyperv_pdpte = &hyperv_pdpt[pdpt_index];
		slat_pdpte* const hook_pdpte = &hook_pdpt[pdpt_index];

		hook_pdpte->flags = hyperv_pdpte->flags;

		if (slat::is_pte_present(hyperv_pdpte) == 0)
		{
			continue;
		}

		if (slat::is_pte_large(hyperv_pdpte) == 0)
		{
			const slat_pde* const hyperv_pd = slat::get_pde(hyperv_pdpte, { });
			const auto hook_pd = static_cast<slat_pde*>(heap_manager::allocate_page(heap_ctx));

			hook_pdpte->page_frame_number = memory_manager::unmap_host_physical(hook_pd) >> 12;

			make_pd_copy(hyperv_pd, hook_pd, heap_ctx, make_non_executable);
		}
		else if (make_non_executable)
		{
#ifdef _INTELMACHINE
			hook_pdpte->execute_access = 0;
#else
			hook_pdpte->execute_disable = 1;
#endif
		}
	}
}

void slat::make_pml4_copy(const slat_pml4e* const hyperv_pml4, slat_pml4e* const hook_pml4, heap_manager::context_t* heap_ctx, const std::uint8_t make_non_executable)
{
	for (std::uint64_t pml4_index = 0; pml4_index < 512; pml4_index++)
	{
		const slat_pml4e* const hyperv_pml4e = &hyperv_pml4[pml4_index];
		slat_pml4e* const hook_pml4e = &hook_pml4[pml4_index];

		hook_pml4e->flags = hyperv_pml4e->flags;

		if (is_pte_present(hyperv_pml4e) == 0)
		{
			continue;
		}

		const slat_pdpte* const hyperv_pdpt = get_pdpte(hyperv_pml4e, { });
		const auto hook_pdpt = static_cast<slat_pdpte*>(heap_manager::allocate_page(heap_ctx));

		hook_pml4e->page_frame_number = memory_manager::unmap_host_physical(hook_pdpt) >> 12;

		make_pdpt_copy(hyperv_pdpt, hook_pdpt, heap_ctx, make_non_executable);
	}
}
