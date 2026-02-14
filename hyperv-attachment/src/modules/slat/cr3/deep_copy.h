#pragma once
#include <cstdint>
#include "../slat_def.h"

namespace heap_manager { struct context_t; }

namespace slat
{
	void make_pml4_copy(const slat_pml4e* hyperv_pml4, slat_pml4e* hook_pml4, heap_manager::context_t* heap_ctx, std::uint8_t make_non_executable);
}
