#pragma once
#include <cstdint>
#include "../slat_def.h"

union virtual_address_t;

namespace heap_manager { struct context_t; }

namespace slat
{
	slat_pml4e* get_pml4e(cr3 slat_cr3, virtual_address_t guest_physical_address);
	slat_pdpte* get_pdpte(const slat_pml4e* pml4e, virtual_address_t guest_physical_address);
	slat_pde* get_pde(const slat_pdpte* pdpte, virtual_address_t guest_physical_address);
	slat_pte* get_pte(const slat_pde* pde, virtual_address_t guest_physical_address);

	slat_pde* get_pde(cr3 slat_cr3, virtual_address_t guest_physical_address, heap_manager::context_t* heap_ctx, std::uint8_t force_split_pages = 0);
	slat_pte* get_pte(cr3 slat_cr3, virtual_address_t guest_physical_address, heap_manager::context_t* heap_ctx, std::uint8_t force_split_pages = 0, std::uint8_t* paging_split_state = nullptr);

	std::uint8_t split_2mb_pde(slat_pde_2mb* large_pde, heap_manager::context_t* heap_ctx);
	std::uint8_t split_1gb_pdpte(slat_pdpte_1gb* large_pdpte, heap_manager::context_t* heap_ctx);

	std::uint8_t merge_4kb_pt(cr3 slat_cr3, virtual_address_t guest_physical_address, heap_manager::context_t* heap_ctx);

	std::uint8_t is_pte_present(const void* pte_in);
	std::uint8_t is_pte_large(const void* pte_in);
}
