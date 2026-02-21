#pragma once
#include <cstdint>

union virtual_address_t;

namespace slat { struct context_t; }
namespace heap_manager { struct context_t; }

namespace slat::hook
{
	void set_up_entries(slat::context_t* ctx, heap_manager::context_t* heap_ctx);

	std::uint64_t add(slat::context_t* ctx, virtual_address_t target_guest_physical_address, virtual_address_t shadow_guest_physical_address);
	std::uint64_t add_by_host_physical(slat::context_t* ctx, virtual_address_t target_guest_physical_address, std::uint64_t shadow_host_physical_address);
	std::uint64_t hide_payload_memory(slat::context_t* ctx, virtual_address_t target_guest_physical_address);
	std::uint64_t remove(slat::context_t* ctx, virtual_address_t guest_physical_address);
}
