#pragma once
#include <ia32-doc/ia32.hpp>
#include <cstdint>

namespace slat
{
	cr3 hyperv_cr3();
	cr3 hook_cr3();

	cr3 get_cr3();
	void set_cr3(cr3 slat_cr3);

	void invept_single_context(cr3 slat_cr3);
	void flush_current_logical_processor_cache(std::uint8_t has_slat_cr3_changed = 0);
	void flush_all_logical_processors_cache();

	void set_up_hyperv_cr3();
	void set_up_hook_cr3();
} 
