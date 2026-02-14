#pragma once
#include <cstdint>

namespace slat { struct context_t; }

namespace slat::hook
{
	class entry_t
	{
	protected:
		std::uint64_t next_ : 48;
		std::uint64_t original_read_access_ : 1;
		std::uint64_t original_write_access_ : 1;
		std::uint64_t original_execute_access_ : 1;
		std::uint64_t paging_split_state_ : 1;
		std::uint64_t original_pfn_ : 36;
		std::uint64_t reserved_ : 40;

	public:
		[[nodiscard]] entry_t* next() const;
		void set_next(entry_t* next_entry);

		[[nodiscard]] std::uint64_t original_pfn() const;
		void set_original_pfn(std::uint64_t original_pfn);

		[[nodiscard]] std::uint64_t original_read_access() const;
		[[nodiscard]] std::uint64_t original_write_access() const;
		[[nodiscard]] std::uint64_t original_execute_access() const;
		[[nodiscard]] std::uint64_t paging_split_state() const;

		void set_original_read_access(std::uint64_t original_read_access);
		void set_original_write_access(std::uint64_t original_write_access);
		void set_original_execute_access(std::uint64_t original_execute_access);
		void set_paging_split_state(std::uint64_t paging_split_state);

		static entry_t* find(slat::context_t* ctx, std::uint64_t target_original_4kb_pfn, entry_t** previous_entry_out = nullptr);
		static entry_t* find_in_2mb_range(slat::context_t* ctx, std::uint64_t target_original_4kb_pfn, const entry_t* excluding_hook = nullptr);
		static entry_t* find_closest_in_2mb_range(slat::context_t* ctx, std::uint64_t target_original_4kb_pfn, const entry_t* excluding_hook = nullptr);
	};
}
