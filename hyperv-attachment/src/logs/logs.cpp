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

/**
 * @description 初始化日志缓存与索引。
 * @param {void} 无。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * logs::set_up();
 */
void logs::set_up()
{
	// 业务说明：分配日志缓存页并初始化日志索引。
	// 输入：无；输出：stored_logs 与 stored_log_max；规则：连续页分配；异常：不抛出。
	const std::uint64_t stored_logs_pages = 4; // must be at least 1
	const std::uint64_t stored_logs_size = stored_logs_pages * 0x1000;

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

/**
 * @description 追加一条 TrapFrame 日志。
 * @param {const trap_frame_log_t&} trap_frame TrapFrame 日志数据。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * logs::add_log(frame);
 */
void logs::add_log(const trap_frame_log_t& trap_frame)
{
	// 业务说明：并发安全地写入日志缓存。
	// 输入：trap_frame；输出：缓存更新；规则：超过上限则忽略；异常：不抛出。
	log_mutex.lock();

	const std::uint16_t index = stored_log_index;

	if (index < stored_log_max)
	{
		stored_logs[index] = trap_frame;

		stored_log_index++;
	}

	log_mutex.release();
}

/**
 * @description 输出格式化日志到文本缓冲区。
 * @param {const char*} format 格式化字符串。
 * @param {...} 可变参数。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * logs::print("Value=%p\n", value);
 */
void logs::print(const char* format, ...)
{
	// 业务说明：获取文本日志锁并按格式写入缓冲区。
	// 输入：format/args；输出：文本缓冲更新；规则：锁失败则退出；异常：不抛出。
	va_list variadic_args;
	va_start(variadic_args, format);

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
		va_end(variadic_args);
		return;
	}

	// 业务说明：解析格式字符串并按类型写入缓冲区。
	// 输入：format/args；输出：缓冲区内容更新；规则：检查剩余空间；异常：不抛出。
	while (*format)
	{
		if (*format == '%' && *(format + 1))
		{
			format++;
			if (*format == 's')
			{
				const char* s = va_arg(variadic_args, const char*);
				while (s && *s && g_text_log_index < sizeof(g_text_log_buffer) - 1)
				{
					g_text_log_buffer[g_text_log_index++] = *s++;
				}
			}
			else if (*format == 'x' || *format == 'p')
			{
				std::uint64_t val = va_arg(variadic_args, std::uint64_t);
				for (int i = 15; i >= 0; i--)
				{
					char c = "0123456789ABCDEF"[(val >> (i * 4)) & 0xF];
					if (g_text_log_index < sizeof(g_text_log_buffer) - 1)
						g_text_log_buffer[g_text_log_index++] = c;
				}
			}
			else if (*format == 'd')
			{
				std::uint64_t val = va_arg(variadic_args, std::uint64_t);
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
	va_end(variadic_args);
}

/**
 * @description 将 TrapFrame 日志刷写到来宾缓冲区。
 * @param {const cr3} slat_cr3 SLAT CR3。
 * @param {const std::uint64_t} guest_virtual_buffer 来宾缓冲区地址。
 * @param {const cr3} guest_cr3 来宾 CR3。
 * @param {const std::uint16_t} count 需要刷新的日志条数。
 * @return {std::uint8_t} 是否刷写成功。
 * @throws {无} 不抛出异常。
 * @example
 * const auto ok = logs::flush(slat_cr3, buffer, guest_cr3, count);
 */
std::uint8_t logs::flush(const cr3 slat_cr3, const std::uint64_t guest_virtual_buffer, const cr3 guest_cr3, const std::uint16_t count)
{
	// 业务说明：计算可用日志数量并写入来宾内存。
	// 输入：slat_cr3/guest_virtual_buffer/guest_cr3/count；输出：写入结果；规则：写入后更新索引；异常：不抛出。
	log_mutex.lock();

	const std::uint16_t actual_count = crt::min(count, stored_log_index);

	const std::uint16_t copy_start_index = stored_log_index - actual_count;
	const std::uint64_t write_size = sizeof(trap_frame_log_t) * actual_count;

	const std::uint64_t bytes_written = memory_manager::operate_on_guest_virtual_memory(slat_cr3, &stored_logs[copy_start_index], guest_virtual_buffer, guest_cr3, write_size, memory_operation_t::write_operation);

	stored_log_index = copy_start_index;

	log_mutex.release();

	return bytes_written == write_size;
}

/**
 * @description 将文本日志缓冲刷写到来宾缓冲区。
 * @param {const cr3} slat_cr3 SLAT CR3。
 * @param {const std::uint64_t} guest_virtual_buffer 来宾缓冲区地址。
 * @param {const cr3} guest_cr3 来宾 CR3。
 * @param {const std::uint64_t} buffer_size 来宾缓冲区大小。
 * @return {std::uint64_t} 实际写入字节数。
 * @throws {无} 不抛出异常。
 * @example
 * const auto bytes = logs::flush_to_guest(slat_cr3, buffer, guest_cr3, size);
 */
std::uint64_t logs::flush_to_guest(const cr3 slat_cr3, const std::uint64_t guest_virtual_buffer, const cr3 guest_cr3, const std::uint64_t buffer_size)
{
	// 业务说明：将文本缓冲复制到来宾，并维护剩余内容。
	// 输入：slat_cr3/guest_virtual_buffer/guest_cr3/buffer_size；输出：写入字节数；规则：写入后前移剩余；异常：不抛出。
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
