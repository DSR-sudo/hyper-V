#include "interrupts.h"
#include "../memory_manager/heap_manager.h"
#include "../slat/cr3/cr3.h"

#include "ia32-doc/ia32.hpp"
#include <intrin.h>

extern "C"
{
    void nmi_standalone_entry();
    void nmi_entry();
}

namespace
{
    // 业务说明：私有变量已移除，转而使用 context_t 传递状态。
}

/**
 * @description 安装 NMI 处理入口并保存原处理器地址。
 * @param {interrupts::context_t*} ctx 中断上下文。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * set_up_nmi_handling(ctx);
 */
static void set_up_nmi_handling(interrupts::context_t* ctx)
{
    // 业务说明：读取 IDT 并替换 NMI 向量指向自定义入口。
    // 输入：ctx；输出：NMI 入口更新；规则：原入口保留在 ctx 中；异常：不抛出。
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
        if (ctx->original_nmi_handler_storage != nullptr)
        {
            const std::uint64_t original_handler =
                (static_cast<std::uint64_t>(new_gate.offset_high) << 32) |
                (static_cast<std::uint64_t>(new_gate.offset_middle) << 16) |
                static_cast<std::uint64_t>(new_gate.offset_low);
            *ctx->original_nmi_handler_storage = original_handler;
        }
    }

    new_gate.offset_low = new_handler & 0xFFFF;
    new_gate.offset_middle = (new_handler >> 16) & 0xFFFF;
    new_gate.offset_high = (new_handler >> 32) & 0xFFFFFFFF;

    *nmi_gate = new_gate;
}

/**
 * @description 初始化中断子系统与 NMI 状态。
 * @param {interrupts::context_t*} ctx 中断上下文。
 * @param {apic_t*} apic_instance APIC 实例。
 * @param {crt::bitmap_t*} nmi_ready_bitmap NMI 就绪位图。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * interrupts::set_up(ctx, apic, bitmap);
 */
void interrupts::set_up(context_t* ctx, apic_t* apic_instance, crt::bitmap_t* nmi_ready_bitmap, std::uint64_t* original_nmi_handler_storage)
{
    // 业务说明：配置中断上下文并安装 NMI 入口。
    // 输入：ctx/apic/bitmap；输出：上下文初始化完成；规则：工具模块不持有这些状态；异常：不抛出。
    ctx->apic = apic_instance;
    ctx->nmi_ready_bitmap = nmi_ready_bitmap;
    ctx->original_nmi_handler_storage = original_nmi_handler_storage;

#ifdef _INTELMACHINE
    set_up_nmi_handling(ctx);
#endif
}

/**
 * @description 标记所有处理器 NMI 就绪。
 * @param {interrupts::context_t*} ctx 中断上下文。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * interrupts::set_all_nmi_ready(ctx);
 */
void interrupts::set_all_nmi_ready(context_t* ctx)
{
    // 业务说明：将位图所有位置 1。
    // 输入：ctx；输出：位图更新；规则：使用上下文中的位图；异常：不抛出。
    ctx->nmi_ready_bitmap->set_all();
}

/**
 * @description 标记特定处理器 NMI 就绪。
 * @param {interrupts::context_t*} ctx 中断上下文。
 * @param {uint64_t} apic_id 处理器 APIC ID。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * interrupts::set_nmi_ready(ctx, id);
 */
void interrupts::set_nmi_ready(context_t* ctx, const uint64_t apic_id)
{
    ctx->nmi_ready_bitmap->set(apic_id);
}

/**
 * @description 清除特定处理器 NMI 就绪标记。
 * @param {interrupts::context_t*} ctx 中断上下文。
 * @param {uint64_t} apic_id 处理器 APIC ID。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * interrupts::clear_nmi_ready(ctx, id);
 */
void interrupts::clear_nmi_ready(context_t* ctx, const uint64_t apic_id)
{
    ctx->nmi_ready_bitmap->clear(apic_id);
}

/**
 * @description 检查特定处理器是否 NMI 就绪。
 * @param {interrupts::context_t*} ctx 中断上下文。
 * @param {uint64_t} apic_id 处理器 APIC ID。
 * @return {crt::bitmap_t::bit_type} 是否就绪。
 * @throws {无} 不抛出异常。
 * @example
 * const auto ready = interrupts::is_nmi_ready(ctx, id);
 */
crt::bitmap_t::bit_type interrupts::is_nmi_ready(context_t* ctx, const uint64_t apic_id)
{
    return ctx->nmi_ready_bitmap->is_set(apic_id);
}

/**
 * @description 处理 NMI VMExit 或中断。
 * @param {interrupts::context_t*} ctx 中断上下文。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * interrupts::process_nmi(ctx);
 */
void interrupts::process_nmi(context_t* ctx)
{
    // 业务说明：清除当前处理器的 NMI 就绪位。
    // 输入：ctx；输出：位图更新；规则：按当前 APIC ID 清除；异常：不抛出。
    clear_nmi_ready(ctx, apic_t::current_apic_id());
}

/**
 * @description 向除自身外的所有处理器发送 NMI IPI。
 * @param {interrupts::context_t*} ctx 中断上下文。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * interrupts::send_nmi_all_but_self(ctx);
 */
void interrupts::send_nmi_all_but_self(context_t* ctx)
{
    // 业务说明：使用 APIC 实例发送广播 NMI。
    // 输入：ctx；输出：IPI 发送；规则：排除自身；异常：不抛出。
    ctx->apic->send_nmi(icr_destination_shorthand_t::all_but_self);
}
