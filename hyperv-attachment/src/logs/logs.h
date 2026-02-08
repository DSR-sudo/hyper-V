#pragma once
#include <structures/trap_frame.h>
#include "ia32-doc/ia32.hpp"

namespace logs
{
	void set_up();

	void add_log(const trap_frame_log_t& trap_frame);
	std::uint8_t flush(cr3 slat_cr3, std::uint64_t guest_virtual_buffer, cr3 guest_cr3, std::uint16_t count);

	void print(const char* format, ...);
	std::uint64_t flush_to_guest(cr3 slat_cr3, std::uint64_t guest_virtual_buffer, cr3 guest_cr3, std::uint64_t buffer_size);

	inline trap_frame_log_t* stored_logs = nullptr;
	inline std::uint16_t stored_log_index = 0;
	inline std::uint16_t stored_log_max = 0;
}
