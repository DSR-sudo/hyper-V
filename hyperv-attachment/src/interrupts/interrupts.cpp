#include "interrupts.h"
#include "../memory_manager/heap_manager.h"
#include "../slat/cr3/cr3.h"

#include "ia32-doc/ia32.hpp"
#include <intrin.h>

extern "C"
{
    std::uint64_t original_nmi_handler = 0;

    void nmi_standalone_entry();
    void nmi_entry();
}

namespace
{
    crt::bitmap_t processor_nmi_states = { };
}

/**
 * @description 安装 NMI 处理入口并保存原处理器地址。
 * @param {void} 无。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * set_up_nmi_handling();
 */
void set_up_nmi_handling()
{
    // 业务说明：读取 IDT 并替换 NMI 向量指向自定义入口。
    // 输入：无；输出：NMI 入口更新；规则：原入口保留以便链式调用；异常：不抛出。
    segment_descriptor_register_64 idtr = { };

    __sidt(&idtr);

    if (idtr.base_address == 0)
    {
        return;
    }

    const auto interrupt_gates = reinterpret_cast<segment_descriptor_interrupt_gate_64*>(idtr.base_address);
    segment_descriptor_interrupt_gate_64* const nmi_gate = &interrupt_gates[2];
    segment_descriptor_interrupt_gate_64 new_gate = *nmi_gate;

    std::uint64_t new_handler = reinterpret_cast<std::uint64_t>(nmi_entry);

    if (new_gate.present == 0)
    {
        constexpr segment_selector gate_segment_selector = { .index = 1 };

        new_gate.segment_selector = gate_segment_selector.flags;
        new_gate.type = SEGMENT_DESCRIPTOR_TYPE_INTERRUPT_GATE;
        new_gate.present = 1;

        new_handler = reinterpret_cast<std::uint64_t>(nmi_standalone_entry);
    }
    else
    {
        original_nmi_handler = nmi_gate->offset_low | (nmi_gate->offset_middle << 16) | (static_cast<uint64_t>(nmi_gate->offset_high) << 32);
    }

    new_gate.offset_low = new_handler & 0xFFFF;
    new_gate.offset_middle = (new_handler >> 16) & 0xFFFF;
    new_gate.offset_high = (new_handler >> 32) & 0xFFFFFFFF;

    *nmi_gate = new_gate;
}

/**
 * @description 初始化中断子系统与 NMI 状态。
 * @param {void} 无。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * interrupts::set_up();
 */
void interrupts::set_up()
{
    // 业务说明：初始化处理器 NMI 状态位图并创建 APIC 实例。
    // 输入：无；输出：位图与 APIC 就绪；规则：Intel 平台安装 NMI 入口；异常：不抛出。
    constexpr std::uint64_t processor_nmi_state_count = 0x1000 / sizeof(crt::bitmap_t::size_type);

    processor_nmi_states.set_value(static_cast<crt::bitmap_t::pointer>(heap_manager::allocate_page()));
    processor_nmi_states.set_count(processor_nmi_state_count);

    apic = apic_t::create_instance();

#ifdef _INTELMACHINE
    set_up_nmi_handling();
#endif
}

/**
 * @description 标记所有处理器 NMI 就绪。
 * @param {void} 无。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * interrupts::set_all_nmi_ready();
 */
void interrupts::set_all_nmi_ready()
{
    // 业务说明：将位图全部置位，允许所有处理器响应 NMI。
    // 输入：无；输出：位图更新；规则：全部置位；异常：不抛出。
    processor_nmi_states.set_all();
}

/**
 * @description 标记指定处理器 NMI 就绪。
 * @param {const std::uint64_t} apic_id 目标处理器 APIC ID。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * interrupts::set_nmi_ready(apic_id);
 */
void interrupts::set_nmi_ready(const std::uint64_t apic_id)
{
    // 业务说明：设置指定 APIC ID 的位图状态为就绪。
    // 输入：apic_id；输出：位图更新；规则：按索引置位；异常：不抛出。
    processor_nmi_states.set(apic_id);
}

/**
 * @description 清除指定处理器 NMI 就绪标记。
 * @param {const std::uint64_t} apic_id 目标处理器 APIC ID。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * interrupts::clear_nmi_ready(apic_id);
 */
void interrupts::clear_nmi_ready(const std::uint64_t apic_id)
{
    // 业务说明：清除指定 APIC ID 的就绪标记。
    // 输入：apic_id；输出：位图更新；规则：按索引清零；异常：不抛出。
    processor_nmi_states.clear(apic_id);
}

/**
 * @description 查询指定处理器 NMI 就绪状态。
 * @param {const std::uint64_t} apic_id 目标处理器 APIC ID。
 * @return {crt::bitmap_t::bit_type} 是否就绪。
 * @throws {无} 不抛出异常。
 * @example
 * const auto ready = interrupts::is_nmi_ready(apic_id);
 */
crt::bitmap_t::bit_type interrupts::is_nmi_ready(const std::uint64_t apic_id)
{
    // 业务说明：读取位图中的就绪标记。
    // 输入：apic_id；输出：就绪标记；规则：按索引读取；异常：不抛出。
    return processor_nmi_states.is_set(apic_id);
}

/**
 * @description 处理 NMI 并刷新当前处理器缓存。
 * @param {void} 无。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * interrupts::process_nmi();
 */
void interrupts::process_nmi()
{
    // 业务说明：判断当前处理器就绪状态后执行缓存刷新。
    // 输入：无；输出：缓存刷新；规则：就绪才处理；异常：不抛出。
    const std::uint64_t current_apic_id = apic_t::current_apic_id();

    if (is_nmi_ready(current_apic_id) == 1)
    {
        slat::flush_current_logical_processor_cache();

        clear_nmi_ready(current_apic_id);
    }
}

/**
 * @description 向除当前处理器外的所有处理器发送 NMI。
 * @param {void} 无。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * interrupts::send_nmi_all_but_self();
 */
void interrupts::send_nmi_all_but_self()
{
    // 业务说明：通过 APIC 广播 NMI。
    // 输入：无；输出：NMI 广播；规则：不包含当前处理器；异常：不抛出。
    apic->send_nmi(icr_destination_shorthand_t::all_but_self);
}
