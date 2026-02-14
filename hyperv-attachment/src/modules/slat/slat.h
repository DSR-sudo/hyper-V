#pragma once
#include <ia32-doc/ia32.hpp>
#include <cstdint>
#include <atomic>
#include "../crt/crt.h"

union virtual_address_t;

namespace heap_manager { struct context_t; }

namespace slat
{
	namespace hook { class entry_t; }
}

namespace slat
{
	struct context_t
	{
		std::atomic<std::uint64_t> dummy_page_pfn;
		cr3 hook_slat_cr3;
		void* hook_slat_pml4;
		cr3 hyperv_slat_cr3;

		crt::mutex_t hook_mutex = { };
		slat::hook::entry_t* available_hook_list_head = nullptr;
		slat::hook::entry_t* used_hook_list_head = nullptr;
		std::uint8_t is_first_slat_hook = 1;

		// 堆隐藏状态
		std::atomic<std::uint64_t> current_shared_address;
		std::atomic<bool> initialization_flag;

		heap_manager::context_t* heap_ctx;
	};

	void set_up(context_t* ctx, heap_manager::context_t* heap_ctx);
	void process_first_vmexit(context_t* ctx);

	std::uint64_t translate_guest_physical_address(cr3 slat_cr3, virtual_address_t guest_physical_address, std::uint64_t* size_left_of_page = nullptr);

	std::uint8_t hide_heap_pages(context_t* ctx, cr3 slat_cr3, std::uint64_t heap_base, std::uint64_t heap_size);

	std::uint64_t hide_physical_page_from_guest(context_t* ctx, cr3 slat_cr3, virtual_address_t guest_physical_address);
	std::uint64_t hide_physical_page_from_guest(context_t* ctx, virtual_address_t guest_physical_address);
}
