#pragma once
#include <cstdint>

#include "../crt/crt.h"

namespace heap_manager
{
	class heap_entry_t
	{
	public:
		[[nodiscard]] heap_entry_t* next() const;
		void set_next(heap_entry_t* next);

	protected:
		heap_entry_t* next_ = nullptr;
	};

	struct context_t
	{
		heap_entry_t* free_block_list_head;
		crt::mutex_t allocation_mutex;
		std::uint64_t initial_physical_base;
		std::uint64_t initial_size;
	};

	void set_up(context_t* ctx, void* heap_base, std::uint64_t heap_size);

	void* allocate_page(context_t* ctx);
	std::uint64_t allocate_physical_page(context_t* ctx);

	void free_page(context_t* ctx, void* allocation_base);

	std::uint64_t get_free_page_count(context_t* ctx);
}
