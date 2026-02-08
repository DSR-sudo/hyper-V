#include "cr3.h"

#include "../slat.h"
#include "../slat_def.h"
#include "deep_copy.h"
#include "pte.h"

#include "../../memory_manager/memory_manager.h"
#include "../../memory_manager/heap_manager.h"
#include "../../interrupts/interrupts.h"
#include "../../arch/arch.h"

#ifdef _INTELMACHINE
extern "C" void invalidate_ept_mappings(invept_type type, const invept_descriptor& descriptor);
#endif

namespace
{
	cr3 hook_slat_cr3 = { };
	slat_pml4e* hook_slat_pml4 = nullptr;

	cr3 hyperv_slat_cr3 = { };
}

cr3 slat::hyperv_cr3()
{
	return hyperv_slat_cr3;
}

cr3 slat::hook_cr3()
{
	return hook_slat_cr3;
}

cr3 slat::get_cr3()
{
	return arch::get_slat_cr3();
}

void slat::set_cr3(const cr3 slat_cr3)
{
	arch::set_slat_cr3(slat_cr3);

	invept_single_context(slat_cr3);
}

void slat::invept_single_context(const cr3 slat_cr3)
{
#ifdef _INTELMACHINE
	const invept_descriptor descriptor = { .ept_pointer = slat_cr3.flags, .reserved = 0 };
	invalidate_ept_mappings(invept_type::invept_single_context, descriptor);
#endif
}

void slat::flush_current_logical_processor_cache(const std::uint8_t has_slat_cr3_changed)
{
#ifdef _INTELMACHINE
	(void)has_slat_cr3_changed;
	invept_single_context(get_cr3());
#else
	vmcb_t* const vmcb = arch::get_vmcb();

	vmcb->control.tlb_control = tlb_control_t::flush_guest_tlb_entries;

	if (has_slat_cr3_changed == 1)
	{
		vmcb->control.clean.nested_paging = 0;
	}
#endif
}

void slat::flush_all_logical_processors_cache()
{
	flush_current_logical_processor_cache();

	interrupts::set_all_nmi_ready();
	interrupts::send_nmi_all_but_self();
}

void set_up_slat_cr3(cr3* const slat_cr3, slat_pml4e** const slat_pml4)
{
	*slat_pml4 = static_cast<slat_pml4e*>(heap_manager::allocate_page());

	crt::set_memory(*slat_pml4, 0, sizeof(slat_pml4e) * 512);

	const std::uint64_t pml4_physical_address = memory_manager::unmap_host_physical(*slat_pml4);

	*slat_cr3 = slat::hyperv_cr3();
	slat_cr3->address_of_page_directory = pml4_physical_address >> 12;
}

void slat::set_up_hyperv_cr3()
{
	hyperv_slat_cr3 = get_cr3();
}

void slat::set_up_hook_cr3()
{
	set_up_slat_cr3(&hook_slat_cr3, &hook_slat_pml4);

	const slat_pml4e* const hyperv_pml4 = get_pml4e(slat::hyperv_cr3(), { });

#ifdef _INTELMACHINE
	make_pml4_copy(hyperv_pml4, hook_slat_pml4, 0);
#else
	make_pml4_copy(hyperv_pml4, hook_slat_pml4, 1);
#endif

	// the deep copy should contain already the hidden pages
	// as we hid them in the Hyper-V slat cr3, but this is just to make sure
	slat::hide_heap_pages(hook_cr3());
}

