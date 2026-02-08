#include "logs.h"
#include "../memory_manager/heap_manager.h"
#include "../memory_manager/memory_manager.h"
#include "../crt/crt.h"
#include <cstdarg>
#include <cstdint>
#include <intrin.h>

namespace
{
	crt::mutex_t log_mutex = { };

	char g_text_log_buffer[64 * 1024] = { 0 };
	std::uint32_t g_text_log_index = 0;
	crt::mutex_t text_log_mutex = { };
}

void logs::set_up()
{
	constexpr std::uint64_t stored_logs_pages = 4; // must be at least 1
	constexpr std::uint64_t stored_logs_size = stored_logs_pages * 0x1000;

	// will be done in initialization, so will be contiguous
	stored_logs = static_cast<trap_frame_log_t*>(heap_manager::allocate_page());

	// reserve those other pages (will be contiguous)
	for (std::uint64_t i = 0; i < stored_logs_pages - 1; i++)
	{
		heap_manager::allocate_page();
	}

	stored_log_max = stored_logs_size / sizeof(trap_frame_log_t);

	print("Hypervisor logging initialized.\n");
}

void logs::add_log(const trap_frame_log_t& trap_frame)
{
	log_mutex.lock();

	const std::uint16_t index = stored_log_index;

	if (index < stored_log_max)
	{
		stored_logs[index] = trap_frame;

		stored_log_index++;
	}

	log_mutex.release();
}

void logs::print(const char* format, ...)
{
	va_list args;
	va_start(args, format);

	bool locked = false;
	for (int retry = 0; retry < 100; retry++)
	{
		if (text_log_mutex.try_lock())
		{
			locked = true;
			break;
		}
		_mm_pause();
	}

	if (!locked)
	{
		va_end(args);
		return;
	}

	while (*format)
	{
		if (*format == '%' && *(format + 1))
		{
			format++;
			if (*format == 's')
			{
				const char* s = va_arg(args, const char*);
				while (s && *s && g_text_log_index < sizeof(g_text_log_buffer) - 1)
				{
					g_text_log_buffer[g_text_log_index++] = *s++;
				}
			}
			else if (*format == 'x' || *format == 'p')
			{
				std::uint64_t val = va_arg(args, std::uint64_t);
				for (int i = 15; i >= 0; i--)
				{
					char c = "0123456789ABCDEF"[(val >> (i * 4)) & 0xF];
					if (g_text_log_index < sizeof(g_text_log_buffer) - 1)
						g_text_log_buffer[g_text_log_index++] = c;
				}
			}
			else if (*format == 'd')
			{
				std::uint64_t val = va_arg(args, std::uint64_t);
				if (val == 0)
				{
					if (g_text_log_index < sizeof(g_text_log_buffer) - 1)
						g_text_log_buffer[g_text_log_index++] = '0';
				}
				else
				{
					char tmp[20];
					int t = 0;
					while (val > 0) { tmp[t++] = static_cast<char>((val % 10) + '0'); val /= 10; }
					while (t > 0)
					{
						if (g_text_log_index < sizeof(g_text_log_buffer) - 1)
							g_text_log_buffer[g_text_log_index++] = tmp[--t];
					}
				}
			}
		}
		else
		{
			if (g_text_log_index < sizeof(g_text_log_buffer) - 1)
			{
				g_text_log_buffer[g_text_log_index++] = *format;
			}
		}
		format++;
	}

	text_log_mutex.release();
	va_end(args);
}

std::uint8_t logs::flush(const cr3 slat_cr3, const std::uint64_t guest_virtual_buffer, const cr3 guest_cr3, const std::uint16_t count)
{
	log_mutex.lock();

	const std::uint16_t actual_count = crt::min(count, stored_log_index);

	const std::uint16_t copy_start_index = stored_log_index - actual_count;
	const std::uint64_t write_size = sizeof(trap_frame_log_t) * actual_count;

	const std::uint64_t bytes_written = memory_manager::operate_on_guest_virtual_memory(slat_cr3, &stored_logs[copy_start_index], guest_virtual_buffer, guest_cr3, write_size, memory_operation_t::write_operation);

	stored_log_index = copy_start_index;

	log_mutex.release();

	return bytes_written == write_size;
}

std::uint64_t logs::flush_to_guest(const cr3 slat_cr3, const std::uint64_t guest_virtual_buffer, const cr3 guest_cr3, const std::uint64_t buffer_size)
{
	text_log_mutex.lock();

	const std::uint32_t current_index = g_text_log_index;
	if (current_index == 0)
	{
		text_log_mutex.release();
		return 0;
	}

	const std::uint32_t copy_size = static_cast<std::uint32_t>(crt::min(buffer_size, static_cast<std::uint64_t>(current_index)));

	const std::uint64_t bytes_written = memory_manager::operate_on_guest_virtual_memory(slat_cr3, g_text_log_buffer, guest_virtual_buffer, guest_cr3, copy_size, memory_operation_t::write_operation);

	if (bytes_written > 0)
	{
		const std::uint32_t remaining = current_index - static_cast<std::uint32_t>(bytes_written);
		if (remaining > 0)
		{
			crt::copy_memory(g_text_log_buffer, g_text_log_buffer + bytes_written, remaining);
		}
		g_text_log_index = remaining;
		crt::set_memory(g_text_log_buffer + remaining, 0, sizeof(g_text_log_buffer) - remaining);
	}

	text_log_mutex.release();

	return bytes_written;
}
