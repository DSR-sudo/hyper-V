#pragma once
#include <cstdint>

union virtual_address_t;

namespace slat { struct context_t; }
namespace heap_manager { struct context_t; }

namespace slat::hook
{
	void set_up_entries(slat::context_t* ctx, heap_manager::context_t* heap_ctx);

	std::uint64_t add(slat::context_t* ctx, virtual_address_t target_guest_physical_address, virtual_address_t shadow_guest_physical_address);
	std::uint64_t remove(slat::context_t* ctx, virtual_address_t guest_physical_address);
}
