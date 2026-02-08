#include "hook.h"
#include "hook_entry.h"

#include "../cr3/cr3.h"
#include "../cr3/pte.h"
#include "../slat_def.h"
#include "../slat.h"

#include "../../memory_manager/heap_manager.h"

#include "../../structures/virtual_address.h"
#include "../../crt/crt.h"

#ifndef _INTELMACHINE
#include "amd_page_split.h"
#endif

namespace
{
	crt::mutex_t hook_mutex = { };
}

static void process_first_slat_hook()
{
	static std::uint8_t is_first_slat_hook = 1;

	if (is_first_slat_hook)
	{
		is_first_slat_hook = 0;

		slat::set_up_hook_cr3();
	}
}

void slat::hook::set_up_entries()
{
	constexpr std::uint64_t hook_entries_wanted = 0x1000 / sizeof(entry_t);

	void* const hook_entries_allocation = heap_manager::allocate_page();

	available_hook_list_head = static_cast<entry_t*>(hook_entries_allocation);

	entry_t* current_entry = available_hook_list_head;

	for (std::uint64_t i = 0; i < hook_entries_wanted - 1; i++)
	{
		current_entry->set_next(current_entry + 1);
		current_entry->set_original_pfn(0);

		current_entry = current_entry->next();
	}

	current_entry->set_original_pfn(0);
	current_entry->set_next(nullptr);
}

std::uint64_t slat::hook::add(const virtual_address_t target_guest_physical_address, const virtual_address_t shadow_guest_physical_address)
{
	hook_mutex.lock();

	process_first_slat_hook();

	const entry_t* const already_present_hook_entry = entry_t::find(target_guest_physical_address.address >> 12);

	if (already_present_hook_entry != nullptr)
	{
		hook_mutex.release();

		return 0;
	}

	std::uint8_t paging_split_state = 0;

	slat_pte* const target_pte = get_pte(hyperv_cr3(), target_guest_physical_address, 1, &paging_split_state);

	if (target_pte == nullptr)
	{
		hook_mutex.release();

		return 0;
	}

	slat_pte* const hook_target_pte = get_pte(hook_cr3(), target_guest_physical_address, 1);

	if (hook_target_pte == nullptr)
	{
		hook_mutex.release();

		return 0;
	}

	if (paging_split_state == 0)
	{
		const entry_t* const similar_space_hook_entry = entry_t::find_in_2mb_range(target_guest_physical_address.address >> 12);

		if (similar_space_hook_entry != nullptr)
		{
			paging_split_state = static_cast<std::uint8_t>(similar_space_hook_entry->paging_split_state());
		}
	}

	const std::uint64_t shadow_page_host_physical_address = translate_guest_physical_address(hyperv_cr3(), shadow_guest_physical_address);

	if (shadow_page_host_physical_address == 0)
	{
		hook_mutex.release();

		return 0;
	}

	entry_t* const hook_entry = available_hook_list_head;

	if (hook_entry == nullptr)
	{
		hook_mutex.release();

		return 0;
	}

	available_hook_list_head = hook_entry->next();

	hook_entry->set_next(used_hook_list_head);
	hook_entry->set_original_pfn(target_pte->page_frame_number);
	hook_entry->set_paging_split_state(paging_split_state);

	used_hook_list_head = hook_entry;

#ifdef _INTELMACHINE
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
#else
	hook_entry->set_original_execute_access(!target_pte->execute_disable);

	hook_target_pte->execute_disable = 0;
	hook_target_pte->page_frame_number = shadow_page_host_physical_address >> 12;

	fix_split_instructions(hook_cr3(), target_guest_physical_address);

	target_pte->execute_disable = 1;
#endif

	hook_mutex.release();

	// Critical fix: Remove global NMI broadcast, only flush current core cache
	// Avoid all-core DPC wait timeout when Usermode frequently adds hooks
	flush_current_logical_processor_cache();

	return 1;
}

std::uint8_t does_hook_need_merge(const slat::hook::entry_t* const hook_entry, const virtual_address_t guest_physical_address)
{
	if (hook_entry == nullptr)
	{
		return 0;
	}

	const std::uint8_t requires_merge = hook_entry->paging_split_state() == 1;

	if (requires_merge == 0)
	{
		return 0;
	}

	const slat::hook::entry_t* const other_hook = slat::hook::entry_t::find_in_2mb_range(guest_physical_address.address >> 12, hook_entry);

	return other_hook == nullptr;
}

std::uint8_t clean_up_hook_ptes(const virtual_address_t target_guest_physical_address, const slat::hook::entry_t* const hook_entry)
{
	slat_pte* const target_pte = slat::get_pte(slat::hyperv_cr3(), target_guest_physical_address);

	if (target_pte == nullptr)
	{
		return 0;
	}

	slat_pte* const hook_target_pte = slat::get_pte(slat::hook_cr3(), target_guest_physical_address);

	if (hook_target_pte == nullptr)
	{
		return 0;
	}

#ifdef _INTELMACHINE
	target_pte->page_frame_number = hook_entry->original_pfn();

	target_pte->read_access = hook_entry->original_read_access();
	target_pte->write_access = hook_entry->original_write_access();
	target_pte->execute_access = hook_entry->original_execute_access();

	hook_target_pte->read_access = hook_entry->original_read_access();
	hook_target_pte->write_access = hook_entry->original_write_access();
	hook_target_pte->execute_access = hook_entry->original_execute_access();
#else
	target_pte->execute_disable = !hook_entry->original_execute_access();

	hook_target_pte->page_frame_number = hook_entry->original_pfn();
	hook_target_pte->execute_disable = 1;

	unfix_split_instructions(hook_entry, slat::hook_cr3(), target_guest_physical_address);
#endif

	if (does_hook_need_merge(hook_entry, target_guest_physical_address) == 1)
	{
		slat::merge_4kb_pt(slat::hyperv_cr3(), target_guest_physical_address);
		slat::merge_4kb_pt(slat::hook_cr3(), target_guest_physical_address);
	}

	return 1;
}

void clean_up_hook_entry(slat::hook::entry_t* const hook_entry, slat::hook::entry_t* const previous_hook_entry)
{
	if (previous_hook_entry == nullptr)
	{
		slat::hook::used_hook_list_head = hook_entry->next();
	}
	else
	{
		previous_hook_entry->set_next(hook_entry->next());
	}

	hook_entry->set_next(slat::hook::available_hook_list_head);

	slat::hook::available_hook_list_head = hook_entry;
}

std::uint64_t slat::hook::remove(const virtual_address_t guest_physical_address)
{
	hook_mutex.lock();

	entry_t* previous_hook_entry = nullptr;

	entry_t* const hook_entry = entry_t::find(guest_physical_address.address >> 12, &previous_hook_entry);

	if (hook_entry == nullptr)
	{
		hook_mutex.release();

		return 0;
	}

	const std::uint8_t pte_cleanup_status = clean_up_hook_ptes(guest_physical_address, hook_entry);

	clean_up_hook_entry(hook_entry, previous_hook_entry);

	hook_mutex.release();

	// Critical fix: Remove global NMI broadcast, only flush current core cache
	// Avoid all-core DPC wait timeout when Usermode frequently removes hooks
	flush_current_logical_processor_cache();

	return pte_cleanup_status;
}
