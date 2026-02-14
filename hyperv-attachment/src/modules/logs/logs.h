#pragma once
#include <structures/trap_frame.h>
#include "ia32-doc/ia32.hpp"
#include "../crt/crt.h"

namespace logs
{
	struct context_t
	{
		trap_frame_log_t* stored_logs;
		std::uint16_t stored_log_index;
		std::uint16_t stored_log_max;
		crt::mutex_t log_mutex;

		char text_log_buffer[64 * 1024];
		std::uint32_t text_log_index;
		crt::mutex_t text_log_mutex;
	};

	void set_up(context_t* ctx, void* buffer, std::uint64_t buffer_size);

	void add_log(context_t* ctx, const trap_frame_log_t& trap_frame);
	std::uint8_t flush(context_t* ctx, cr3 slat_cr3, std::uint64_t guest_virtual_buffer, cr3 guest_cr3, std::uint16_t count);

	void print(context_t* ctx, const char* format, ...);
	std::uint64_t flush_to_guest(context_t* ctx, cr3 slat_cr3, std::uint64_t guest_virtual_buffer, cr3 guest_cr3, std::uint64_t buffer_size);
}
