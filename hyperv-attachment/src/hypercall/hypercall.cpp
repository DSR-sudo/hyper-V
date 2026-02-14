#include "hypercall.h"
#include "../modules/memory_manager/memory_manager.h"
#include "../modules/memory_manager/heap_manager.h"
#include "../runtime/runtime_context.h"

#include "../modules/slat/slat.h"
#include "../modules/slat/cr3/cr3.h"
#include "../modules/slat/hook/hook.h"

#include "../modules/arch/arch.h"
#include "../modules/logs/logs.h"
#include "../modules/crt/crt.h"

#include <ia32-doc/ia32.hpp>
#include <hypercall/hypercall_def.h>

/**
 * @description 在来宾物理内存与来宾缓冲之间执行读写。
 * @param {const trap_frame_t* const} trap_frame TrapFrame 数据。
 * @param {const memory_operation_t} operation 读/写操作类型。
 * @return {std::uint64_t} 实际拷贝字节数。
 * @throws {无} 不抛出异常。
 * @example
 * const auto bytes = operate_on_guest_physical_memory(frame, memory_operation_t::read_operation);
 */
std::uint64_t operate_on_guest_physical_memory(const trap_frame_t* const trap_frame, const memory_operation_t operation)
{
    // 业务说明：按页转换来宾地址并执行物理内存读写。
    // 输入：trap_frame/operation；输出：拷贝字节数；规则：转换失败停止；异常：不抛出。
    const cr3 guest_cr3 = arch::get_guest_cr3();
    const cr3 slat_cr3 = slat::hyperv_cr3(&g_runtime_context.slat_ctx);

    const std::uint64_t guest_buffer_virtual_address = trap_frame->r8;
    const std::uint64_t guest_physical_address = trap_frame->rdx;

    std::uint64_t size_left_to_copy = trap_frame->r9;

    std::uint64_t bytes_copied = 0;

    while (size_left_to_copy != 0)
    {
        std::uint64_t size_left_of_destination_slat_page = UINT64_MAX;
        std::uint64_t size_left_of_source_slat_page = UINT64_MAX;

        const std::uint64_t guest_buffer_physical_address = memory_manager::translate_guest_virtual_address(guest_cr3, slat_cr3, { .address = guest_buffer_virtual_address + bytes_copied });

        void* host_destination = memory_manager::map_guest_physical(slat_cr3, guest_buffer_physical_address, &size_left_of_destination_slat_page);
        void* host_source = memory_manager::map_guest_physical(slat_cr3, guest_physical_address + bytes_copied, &size_left_of_source_slat_page);

        if (size_left_of_destination_slat_page == UINT64_MAX || size_left_of_source_slat_page == UINT64_MAX)
        {
            break;
        }

        if (operation == memory_operation_t::write_operation)
        {
            crt::swap(host_source, host_destination);
        }

        const std::uint64_t size_left_of_slat_pages = crt::min(size_left_of_source_slat_page, size_left_of_destination_slat_page);

        const std::uint64_t copy_size = crt::min(size_left_to_copy, size_left_of_slat_pages);

        if (copy_size == 0)
        {
            break;
        }

        crt::copy_memory(host_destination, host_source, copy_size);

        size_left_to_copy -= copy_size;
        bytes_copied += copy_size;
    }

    return bytes_copied;
}

/**
 * @description 在来宾虚拟内存之间执行读写。
 * @param {const trap_frame_t* const} trap_frame TrapFrame 数据。
 * @param {const memory_operation_t} operation 读/写操作类型。
 * @param {const std::uint64_t} address_of_page_directory 源来宾 CR3 页目录基址。
 * @return {std::uint64_t} 实际拷贝字节数。
 * @throws {无} 不抛出异常。
 * @example
 * const auto bytes = operate_on_guest_virtual_memory(frame, memory_operation_t::write_operation, cr3_base);
 */
std::uint64_t operate_on_guest_virtual_memory(const trap_frame_t* const trap_frame, const memory_operation_t operation, const std::uint64_t address_of_page_directory)
{
    // 业务说明：使用源/目标来宾 CR3 进行虚拟地址转换并分段拷贝。
    // 输入：trap_frame/operation/address_of_page_directory；输出：拷贝字节数；规则：任一转换失败停止；异常：不抛出。
    const cr3 guest_source_cr3 = { .address_of_page_directory = address_of_page_directory };

    const cr3 guest_destination_cr3 = arch::get_guest_cr3();
    const cr3 slat_cr3 = slat::hyperv_cr3(&g_runtime_context.slat_ctx);

    const std::uint64_t guest_destination_virtual_address = trap_frame->rdx;
    const  std::uint64_t guest_source_virtual_address = trap_frame->r8;

    std::uint64_t size_left_to_read = trap_frame->r9;

    std::uint64_t bytes_copied = 0;

    while (size_left_to_read != 0)
    {
        std::uint64_t size_left_of_destination_virtual_page = UINT64_MAX;
        std::uint64_t size_left_of_destination_slat_page = UINT64_MAX;

        std::uint64_t size_left_of_source_virtual_page = UINT64_MAX;
        std::uint64_t size_left_of_source_slat_page = UINT64_MAX;

        const std::uint64_t guest_source_physical_address = memory_manager::translate_guest_virtual_address(guest_source_cr3, slat_cr3, { .address = guest_source_virtual_address + bytes_copied }, &size_left_of_source_virtual_page);
        const std::uint64_t guest_destination_physical_address = memory_manager::translate_guest_virtual_address(guest_destination_cr3, slat_cr3, { .address = guest_destination_virtual_address + bytes_copied }, &size_left_of_destination_virtual_page);

        if (size_left_of_destination_virtual_page == UINT64_MAX || size_left_of_source_virtual_page == UINT64_MAX)
        {
            break;
        }

        void* host_destination = memory_manager::map_guest_physical(slat_cr3, guest_destination_physical_address, &size_left_of_destination_slat_page);
        void* host_source = memory_manager::map_guest_physical(slat_cr3, guest_source_physical_address, &size_left_of_source_slat_page);

    	if (size_left_of_destination_slat_page == UINT64_MAX || size_left_of_source_slat_page == UINT64_MAX)
        {
            break;
        }

        if (operation == memory_operation_t::write_operation)
        {
            crt::swap(host_source, host_destination);
        }

        const std::uint64_t size_left_of_slat_pages = crt::min(size_left_of_source_slat_page, size_left_of_destination_slat_page);
        const std::uint64_t size_left_of_virtual_pages = crt::min(size_left_of_source_virtual_page, size_left_of_destination_virtual_page);

        const std::uint64_t size_left_of_pages = crt::min(size_left_of_slat_pages, size_left_of_virtual_pages);

        const std::uint64_t copy_size = crt::min(size_left_to_read, size_left_of_pages);

        if (copy_size == 0)
        {
            break;
        }

        crt::copy_memory(host_destination, host_source, copy_size);

        size_left_to_read -= copy_size;
        bytes_copied += copy_size;
    }

    return bytes_copied;
}

/**
 * @description 从来宾栈拷贝日志相关的栈数据。
 * @param {std::uint64_t* const} stack_data 输出栈数据数组。
 * @param {const std::uint64_t} stack_data_count 栈数据数量。
 * @param {const cr3} guest_cr3 来宾 CR3。
 * @param {const std::uint64_t} rsp 来宾 RSP。
 * @return {std::uint8_t} 是否拷贝成功。
 * @throws {无} 不抛出异常。
 * @example
 * const auto ok = copy_stack_data_from_log_exit(buf, count, guest_cr3, rsp);
 */
std::uint8_t copy_stack_data_from_log_exit(std::uint64_t* const stack_data, const std::uint64_t stack_data_count, const cr3 guest_cr3, const std::uint64_t rsp)
{
    // 业务说明：按页读取来宾栈数据并拷贝到缓冲区。
    // 输入：stack_data/stack_data_count/guest_cr3/rsp；输出：拷贝结果；规则：地址无效返回失败；异常：不抛出。
    if (rsp == 0)
    {
        return 0;
    }

    const cr3 slat_cr3 = slat::hyperv_cr3(&g_runtime_context.slat_ctx);

    std::uint64_t bytes_read = 0;
    std::uint64_t bytes_remaining = stack_data_count * sizeof(std::uint64_t);

    while (bytes_remaining != 0)
    {
        std::uint64_t virtual_size_left = 0;

        const std::uint64_t rsp_guest_physical_address = memory_manager::translate_guest_virtual_address(guest_cr3, slat_cr3, { .address = rsp + bytes_read }, &virtual_size_left);

        if (rsp_guest_physical_address == 0)
        {
            return 0;
        }

        std::uint64_t physical_size_left = 0;

        // rcx has just been pushed onto stack
        const auto rsp_mapped = static_cast<const std::uint64_t*>(memory_manager::map_guest_physical(slat_cr3, rsp_guest_physical_address, &physical_size_left));

        const std::uint64_t size_left_of_page = crt::min(physical_size_left, virtual_size_left);
        const std::uint64_t size_to_read = crt::min(bytes_remaining, size_left_of_page);

        if (size_to_read == 0)
        {
            return 0;
        }

        crt::copy_memory(reinterpret_cast<std::uint8_t*>(stack_data) + bytes_read, reinterpret_cast<const std::uint8_t*>(rsp_mapped) + bytes_read, size_to_read);

        bytes_remaining -= size_to_read;
        bytes_read += size_to_read;
    }

    return 1;
}

/**
 * @description 将栈数据拷贝到 TrapFrame 日志结构。
 * @param {trap_frame_log_t&} trap_frame TrapFrame 日志结构。
 * @param {const cr3} guest_cr3 来宾 CR3。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * do_stack_data_copy(frame, guest_cr3);
 */
void do_stack_data_copy(trap_frame_log_t& trap_frame, const cr3 guest_cr3)
{
    // 业务说明：读取栈数据并填充日志结构中的栈快照。
    // 输入：trap_frame/guest_cr3；输出：stack_data/rcx/rsp 更新；规则：忽略失败；异常：不抛出。
    constexpr std::uint64_t stack_data_count = trap_frame_log_stack_data_count + 1;

    std::uint64_t stack_data[stack_data_count] = { };

    copy_stack_data_from_log_exit(&stack_data[0], stack_data_count, guest_cr3, trap_frame.rsp);

    crt::copy_memory(&trap_frame.stack_data, &stack_data[1], sizeof(trap_frame.stack_data));

    trap_frame.rcx = stack_data[0];
    trap_frame.rsp += 8; // get rid of the rcx value we push onto stack ourselves
}

/**
 * @description 记录当前处理器状态到日志。
 * @param {trap_frame_log_t} trap_frame TrapFrame 日志结构。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * log_current_state(frame);
 */
void log_current_state(trap_frame_log_t trap_frame)
{
    // 业务说明：补全 CR3/RIP/栈数据并写入日志缓存。
    // 输入：trap_frame；输出：日志新增；规则：获取当前来宾状态；异常：不抛出。
    cr3 guest_cr3 = arch::get_guest_cr3();

    do_stack_data_copy(trap_frame, guest_cr3);

    trap_frame.cr3 = guest_cr3.flags;
    trap_frame.rip = arch::get_guest_rip();

    logs::add_log(&g_runtime_context.log_ctx, trap_frame);
}

/**
 * @description 将日志批量刷写到来宾缓冲区。
 * @param {const trap_frame_t* const} trap_frame TrapFrame 数据。
 * @return {std::uint64_t} 刷写前的日志条数，失败返回 -1。
 * @throws {无} 不抛出异常。
 * @example
 * const auto count = flush_logs(frame);
 */
std::uint64_t flush_logs(const trap_frame_t* const trap_frame)
{
    // 业务说明：按请求数量将日志从宿主缓存写入来宾内存。
    // 输入：trap_frame；输出：写入条数或错误；规则：写入失败返回 -1；异常：不抛出。
    std::uint64_t stored_logs_count = g_runtime_context.log_ctx.stored_log_index;

    const cr3 guest_cr3 = arch::get_guest_cr3();
    const cr3 slat_cr3 = slat::hyperv_cr3(&g_runtime_context.slat_ctx);

    const std::uint64_t guest_virtual_address = trap_frame->rdx;
    const std::uint16_t count = static_cast<std::uint16_t>(trap_frame->r8);

    if (logs::flush(&g_runtime_context.log_ctx, slat_cr3, guest_virtual_address, guest_cr3, count) == 0)
    {
        return -1;
    }

    return stored_logs_count;
}

/**
 * @description 处理来宾 Hypercall 请求。
 * @param {const hypercall_info_t} hypercall_info Hypercall 信息。
 * @param {trap_frame_t* const} trap_frame TrapFrame 指针。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * hypercall::process(info, frame);
 */
void hypercall::process(const hypercall_info_t hypercall_info, trap_frame_t* const trap_frame)
{
    // 业务说明：根据 Hypercall 类型分发到对应处理逻辑。
    // 输入：hypercall_info/trap_frame；输出：trap_frame->rax 结果；规则：未知类型忽略；异常：不抛出。
    if (hypercall_info.call_reserved_data == 0xDEADBEEF)
    {
        // 业务说明：处理日志文本刷写的特殊 Hypercall。
        // 输入：trap_frame；输出：写入字节数；规则：reserved_data 匹配时执行；异常：不抛出。
        const cr3 guest_cr3 = arch::get_guest_cr3();
        const cr3 slat_cr3 = slat::hyperv_cr3(&g_runtime_context.slat_ctx);

        const std::uint64_t buffer_guest_virtual_address = trap_frame->rdx;
        const std::uint64_t buffer_size = trap_frame->r8;

        trap_frame->rax = logs::flush_to_guest(&g_runtime_context.log_ctx, slat_cr3, buffer_guest_virtual_address, guest_cr3, buffer_size);

        return;
    }

    switch (hypercall_info.call_type)
    {
    case hypercall_type_t::guest_physical_memory_operation:
    {
        // 业务说明：执行来宾物理内存读写。
        // 输入：trap_frame；输出：拷贝字节数；规则：按 operation 类型；异常：不抛出。
        const auto memory_operation = static_cast<memory_operation_t>(hypercall_info.call_reserved_data);

        trap_frame->rax = operate_on_guest_physical_memory(trap_frame, memory_operation);

        break;
    }
    case hypercall_type_t::guest_virtual_memory_operation:
    {
        // 业务说明：执行来宾虚拟内存读写。
        // 输入：trap_frame；输出：拷贝字节数；规则：按 operation 类型；异常：不抛出。
        const virt_memory_op_hypercall_info_t virt_memory_op_info = { .value = hypercall_info.value };

        const memory_operation_t memory_operation = virt_memory_op_info.memory_operation;
        const std::uint64_t address_of_page_directory = virt_memory_op_info.address_of_page_directory;

        trap_frame->rax = operate_on_guest_virtual_memory(trap_frame, memory_operation, address_of_page_directory);

        break;
    }
    case hypercall_type_t::translate_guest_virtual_address:
    {
        // 业务说明：转换来宾虚拟地址为物理地址。
        // 输入：trap_frame；输出：物理地址；规则：按目标 CR3 转换；异常：不抛出。
        const virtual_address_t guest_virtual_address = { .address = trap_frame->rdx };

        const cr3 target_guest_cr3 = { .flags = trap_frame->r8 };
        const cr3 slat_cr3 = slat::hyperv_cr3(&g_runtime_context.slat_ctx);

        trap_frame->rax = memory_manager::translate_guest_virtual_address(target_guest_cr3, slat_cr3, guest_virtual_address);

        break;
    }
    case hypercall_type_t::read_guest_cr3:
    {
        // 业务说明：读取当前来宾 CR3。
        // 输入：无；输出：CR3 flags；规则：直接返回；异常：不抛出。
        const cr3 guest_cr3 = arch::get_guest_cr3();

        trap_frame->rax = guest_cr3.flags;

        break;
    }
    case hypercall_type_t::add_slat_code_hook:
    {
        // 业务说明：添加 SLAT 代码 Hook。
        // 输入：目标地址与影子地址；输出：是否成功；规则：调用 Hook 模块；异常：不抛出。
        const virtual_address_t target_guest_physical_address = { .address = trap_frame->rdx };
        const virtual_address_t shadow_page_guest_physical_address = { .address = trap_frame->r8 };

        trap_frame->rax = slat::hook::add(&g_runtime_context.slat_ctx, target_guest_physical_address, shadow_page_guest_physical_address);

        break;
    }
    case hypercall_type_t::remove_slat_code_hook:
    {
        // 业务说明：移除 SLAT 代码 Hook。
        // 输入：目标地址；输出：是否成功；规则：调用 Hook 模块；异常：不抛出。
        const virtual_address_t target_guest_physical_address = { .address = trap_frame->rdx };

        trap_frame->rax = slat::hook::remove(&g_runtime_context.slat_ctx, target_guest_physical_address);

        break;
    }
    case hypercall_type_t::hide_guest_physical_page:
    {
        // 业务说明：隐藏指定来宾物理页。
        // 输入：目标地址；输出：是否成功；规则：调用 SLAT 隐藏；异常：不抛出。
        const virtual_address_t target_guest_physical_address = { .address = trap_frame->rdx };
        const cr3 slat_cr3 = slat::hyperv_cr3(&g_runtime_context.slat_ctx);

        trap_frame->rax = slat::hide_physical_page_from_guest(&g_runtime_context.slat_ctx, slat_cr3, target_guest_physical_address);

        break;
    }
    case hypercall_type_t::log_current_state:
    {
        // 业务说明：记录当前 TrapFrame 状态到日志。
        // 输入：trap_frame；输出：日志新增；规则：复制并记录；异常：不抛出。
        trap_frame_log_t trap_frame_log;

        crt::copy_memory(&trap_frame_log, trap_frame, sizeof(trap_frame_t));

        log_current_state(trap_frame_log);

        break;
    }
    case hypercall_type_t::flush_logs:
    {
        // 业务说明：刷写日志到来宾缓冲区。
        // 输入：trap_frame；输出：写入条数；规则：flush_logs 返回值；异常：不抛出。
        trap_frame->rax = flush_logs(trap_frame);

        break;
    }
    case hypercall_type_t::get_heap_free_page_count:
    {
        // 业务说明：获取堆空闲页数量。
        // 输入：无；输出：空闲页数量；规则：读取堆管理器；异常：不抛出。
        trap_frame->rax = heap_manager::get_free_page_count(&g_runtime_context.heap_ctx);

        break;
    }
    default:
        break;
    }
}
