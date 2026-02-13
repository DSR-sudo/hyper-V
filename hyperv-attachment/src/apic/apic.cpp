#include "apic.h"
#include "apic_intrin.h"

#include "../memory_manager/memory_manager.h"

constexpr uint64_t needed_apic_class_instance_size = sizeof(xapic_t) < sizeof(x2apic_t) ? sizeof(x2apic_t) : sizeof(xapic_t);

#ifdef APIC_RUNTIME_INSTANCE_ALLOCATION
// allocate_memory and free is up to you to implement
extern void* allocate_memory(uint64_t size);
extern void free_memory(void* p, uint64_t size);
#else
static char apic_class_instance_allocation[needed_apic_class_instance_size] = { };
#endif

/**
 * @description 执行 CPUID 叶子 1 获取 APIC 相关信息。
 * @param {void} 无。
 * @return {cpuid_01_t} CPUID 结果结构。
 * @throws {无} 不抛出异常。
 * @example
 * const auto info = perform_cpuid_01();
 */
cpuid_01_t perform_cpuid_01()
{
	// 业务说明：调用 CPUID 指令获取处理器特性。
	// 输入：无；输出：CPUID 结果；规则：叶子 1；异常：不抛出。
	cpuid_01_t cpuid_01;

	apic::intrin::cpuid(reinterpret_cast<int32_t*>(&cpuid_01), 1);

	return cpuid_01;
}

/**
 * @description 启用 APIC 并选择 x2APIC 模式。
 * @param {const uint8_t} use_x2apic 是否启用 x2APIC。
 * @return {uint8_t} 是否启用成功。
 * @throws {无} 不抛出异常。
 * @example
 * apic_t::enable(1);
 */
uint8_t apic_t::enable(const uint8_t use_x2apic)
{
	// 业务说明：写入 APIC 基址 MSR 打开全局 APIC 并设置模式。
	// 输入：use_x2apic；输出：APIC 使能；规则：PFN 为空时使用默认地址；异常：不抛出。
	apic_base_t apic_base = read_apic_base();

	if (apic_base.apic_pfn == 0)
	{
		apic_base.apic_pfn = 0xFEE00;
	}

	apic_base.is_apic_globally_enabled = 1;
	apic_base.is_x2apic = use_x2apic;

	apic::intrin::wrmsr(apic::apic_base_msr, apic_base.flags);

	return 1;
}

/**
 * @description 判断 APIC 是否全局启用。
 * @param {const apic_base_t} apic_base APIC 基址寄存器值。
 * @return {uint8_t} 是否启用。
 * @throws {无} 不抛出异常。
 * @example
 * const auto enabled = apic_t::is_any_enabled(base);
 */
uint8_t apic_t::is_any_enabled(const apic_base_t apic_base)
{
	// 业务说明：检查 APIC 全局使能位。
	// 输入：apic_base；输出：使能状态；规则：读取标志位；异常：不抛出。
	return apic_base.is_apic_globally_enabled;
}

/**
 * @description 判断 x2APIC 是否启用。
 * @param {const apic_base_t} apic_base APIC 基址寄存器值。
 * @return {uint8_t} 是否启用 x2APIC。
 * @throws {无} 不抛出异常。
 * @example
 * const auto enabled = apic_t::is_x2apic_enabled(base);
 */
uint8_t apic_t::is_x2apic_enabled(const apic_base_t apic_base)
{
	// 业务说明：在 APIC 已启用前提下检查 x2APIC 标志位。
	// 输入：apic_base；输出：是否启用 x2APIC；规则：先确认 APIC 使能；异常：不抛出。
	return is_any_enabled(apic_base) == 1 && apic_base.is_x2apic == 1;
}

/**
 * @description 读取 APIC 基址 MSR。
 * @param {void} 无。
 * @return {apic_base_t} APIC 基址寄存器值。
 * @throws {无} 不抛出异常。
 * @example
 * const auto base = apic_t::read_apic_base();
 */
apic_base_t apic_t::read_apic_base()
{
	// 业务说明：通过 RDMSR 读取 APIC 基址寄存器。
	// 输入：无；输出：apic_base；规则：读取 MSR；异常：不抛出。
	return { .flags = apic::intrin::rdmsr(apic::apic_base_msr) };
}

/**
 * @description 获取当前处理器 APIC ID。
 * @param {void} 无。
 * @return {uint32_t} 当前 APIC ID。
 * @throws {无} 不抛出异常。
 * @example
 * const auto apic_id = apic_t::current_apic_id();
 */
uint32_t apic_t::current_apic_id()
{
	// 业务说明：读取 CPUID 获取初始 APIC ID。
	// 输入：无；输出：APIC ID；规则：使用 CPUID 叶子 1；异常：不抛出。
	const cpuid_01_t cpuid_01 = perform_cpuid_01();
	
	return cpuid_01.ebx.initial_apic_id;
}

/**
 * @description 判断处理器是否支持 x2APIC。
 * @param {void} 无。
 * @return {uint8_t} 是否支持 x2APIC。
 * @throws {无} 不抛出异常。
 * @example
 * const auto supported = apic_t::is_x2apic_supported();
 */
uint8_t apic_t::is_x2apic_supported()
{
	// 业务说明：检查 CPUID 扩展标志位。
	// 输入：无；输出：支持标志；规则：读取 CPUID；异常：不抛出。
	const cpuid_01_t cpuid_01 = perform_cpuid_01();

	return cpuid_01.ecx.x2apic_supported == 1;
}

/**
 * @description 构建基础 ICR 发送参数。
 * @param {const uint32_t} vector 中断向量。
 * @param {const icr_delivery_mode_t} delivery_mode 投递模式。
 * @param {const icr_destination_mode_t} destination_mode 目标模式。
 * @return {apic_full_icr_t} ICR 结构。
 * @throws {无} 不抛出异常。
 * @example
 * auto icr = apic_t::make_base_icr(0x40, icr_delivery_mode_t::fixed, icr_destination_mode_t::physical);
 */
apic_full_icr_t apic_t::make_base_icr(const uint32_t vector, const icr_delivery_mode_t delivery_mode, const icr_destination_mode_t destination_mode)
{
	// 业务说明：设置 ICR 的向量、投递模式与触发参数。
	// 输入：vector/delivery_mode/destination_mode；输出：ICR 结构；规则：边沿触发、断言级；异常：不抛出。
	apic_full_icr_t icr = { };

	icr.low.vector = vector;
	icr.low.delivery_mode = delivery_mode;
	icr.low.destination_mode = destination_mode;
	icr.low.trigger_mode = icr_trigger_mode_t::edge;
	icr.low.level = icr_level_t::assert;

	return icr;
}

/**
 * @description 向指定 APIC ID 发送 IPI。
 * @param {const uint32_t} vector 中断向量。
 * @param {const uint32_t} apic_id 目标 APIC ID。
 * @param {const uint8_t} is_lowest_priority 是否最低优先级投递。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * apic->send_ipi(0x40, apic_id, 0);
 */
void apic_t::send_ipi(const uint32_t vector, const uint32_t apic_id, const uint8_t is_lowest_priority)
{
	// 业务说明：构建 ICR 并写入 APIC 寄存器。
	// 输入：vector/apic_id/is_lowest_priority；输出：IPI 发送；规则：按目标 ID 发送；异常：不抛出。
	const icr_delivery_mode_t delivery_mode = is_lowest_priority == 1 ? icr_delivery_mode_t::lowest_priority : icr_delivery_mode_t::fixed;

	apic_full_icr_t icr = make_base_icr(vector, delivery_mode, icr_destination_mode_t::physical);

	set_icr_longhand_destination(icr, apic_id);
	write_icr(icr);
}

/**
 * @description 向简写目标发送 IPI。
 * @param {const uint32_t} vector 中断向量。
 * @param {const icr_destination_shorthand_t} destination_shorthand 目标简写。
 * @param {const uint8_t} is_lowest_priority 是否最低优先级投递。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * apic->send_ipi(0x40, icr_destination_shorthand_t::all_but_self, 0);
 */
void apic_t::send_ipi(const uint32_t vector, const icr_destination_shorthand_t destination_shorthand, const uint8_t is_lowest_priority)
{
	// 业务说明：构建 ICR 并设置简写目标。
	// 输入：vector/destination_shorthand/is_lowest_priority；输出：IPI 发送；规则：使用简写目标；异常：不抛出。
	const icr_delivery_mode_t delivery_mode = is_lowest_priority == 1 ? icr_delivery_mode_t::lowest_priority : icr_delivery_mode_t::fixed;

	apic_full_icr_t icr = make_base_icr(vector, delivery_mode, icr_destination_mode_t::physical);

	icr.low.destination_shorthand = destination_shorthand;

	write_icr(icr);
}

/**
 * @description 向指定 APIC ID 发送 NMI。
 * @param {const uint32_t} apic_id 目标 APIC ID。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * apic->send_nmi(apic_id);
 */
void apic_t::send_nmi(const uint32_t apic_id)
{
	// 业务说明：构建 NMI ICR 并发送到目标处理器。
	// 输入：apic_id；输出：NMI 发送；规则：物理目标；异常：不抛出。
	apic_full_icr_t icr = make_base_icr(0, icr_delivery_mode_t::nmi, icr_destination_mode_t::physical);

	set_icr_longhand_destination(icr, apic_id);
	write_icr(icr);
}

/**
 * @description 向简写目标发送 NMI。
 * @param {const icr_destination_shorthand_t} destination_shorthand 目标简写。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * apic->send_nmi(icr_destination_shorthand_t::all_but_self);
 */
void apic_t::send_nmi(const icr_destination_shorthand_t destination_shorthand)
{
	// 业务说明：构建 NMI ICR 并发送到简写目标。
	// 输入：destination_shorthand；输出：NMI 发送；规则：简写目标；异常：不抛出。
	apic_full_icr_t icr = make_base_icr(0, icr_delivery_mode_t::nmi, icr_destination_mode_t::physical);

	icr.low.destination_shorthand = destination_shorthand;

	write_icr(icr);
}

/**
 * @description 向指定 APIC ID 发送 SMI。
 * @param {const uint32_t} apic_id 目标 APIC ID。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * apic->send_smi(apic_id);
 */
void apic_t::send_smi(const uint32_t apic_id)
{
	// 业务说明：构建 SMI ICR 并发送到目标处理器。
	// 输入：apic_id；输出：SMI 发送；规则：物理目标；异常：不抛出。
	apic_full_icr_t icr = make_base_icr(0, icr_delivery_mode_t::smi, icr_destination_mode_t::physical);

	set_icr_longhand_destination(icr, apic_id);
	write_icr(icr);
}

/**
 * @description 向简写目标发送 SMI。
 * @param {const icr_destination_shorthand_t} destination_shorthand 目标简写。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * apic->send_smi(icr_destination_shorthand_t::self);
 */
void apic_t::send_smi(const icr_destination_shorthand_t destination_shorthand)
{
	// 业务说明：构建 SMI ICR 并发送到简写目标。
	// 输入：destination_shorthand；输出：SMI 发送；规则：简写目标；异常：不抛出。
	apic_full_icr_t icr = make_base_icr(0, icr_delivery_mode_t::smi, icr_destination_mode_t::physical);

	icr.low.destination_shorthand = destination_shorthand;

	write_icr(icr);
}

/**
 * @description 向指定 APIC ID 发送 INIT IPI。
 * @param {const uint32_t} apic_id 目标 APIC ID。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * apic->send_init_ipi(apic_id);
 */
void apic_t::send_init_ipi(const uint32_t apic_id)
{
	// 业务说明：构建 INIT IPI 并发送到目标处理器。
	// 输入：apic_id；输出：INIT IPI 发送；规则：物理目标；异常：不抛出。
	apic_full_icr_t icr = make_base_icr(0, icr_delivery_mode_t::init, icr_destination_mode_t::physical);

	set_icr_longhand_destination(icr, apic_id);
	write_icr(icr);
}

/**
 * @description 向简写目标发送 INIT IPI。
 * @param {const icr_destination_shorthand_t} destination_shorthand 目标简写。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * apic->send_init_ipi(icr_destination_shorthand_t::all_but_self);
 */
void apic_t::send_init_ipi(const icr_destination_shorthand_t destination_shorthand)
{
	// 业务说明：构建 INIT IPI 并发送到简写目标。
	// 输入：destination_shorthand；输出：INIT IPI 发送；规则：简写目标；异常：不抛出。
	apic_full_icr_t icr = make_base_icr(0, icr_delivery_mode_t::init, icr_destination_mode_t::physical);

	icr.low.destination_shorthand = destination_shorthand;

	write_icr(icr);
}

/**
 * @description 向指定 APIC ID 发送 STARTUP IPI。
 * @param {const uint32_t} apic_id 目标 APIC ID。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * apic->send_startup_ipi(apic_id);
 */
void apic_t::send_startup_ipi(const uint32_t apic_id)
{
	// 业务说明：构建 STARTUP IPI 并发送到目标处理器。
	// 输入：apic_id；输出：STARTUP IPI 发送；规则：物理目标；异常：不抛出。
	apic_full_icr_t icr = make_base_icr(0, icr_delivery_mode_t::start_up, icr_destination_mode_t::physical);

	set_icr_longhand_destination(icr, apic_id);
	write_icr(icr);
}

/**
 * @description 向简写目标发送 STARTUP IPI。
 * @param {const icr_destination_shorthand_t} destination_shorthand 目标简写。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * apic->send_startup_ipi(icr_destination_shorthand_t::all_but_self);
 */
void apic_t::send_startup_ipi(const icr_destination_shorthand_t destination_shorthand)
{
	// 业务说明：构建 STARTUP IPI 并发送到简写目标。
	// 输入：destination_shorthand；输出：STARTUP IPI 发送；规则：简写目标；异常：不抛出。
	apic_full_icr_t icr = make_base_icr(0, icr_delivery_mode_t::start_up, icr_destination_mode_t::physical);

	icr.low.destination_shorthand = destination_shorthand;

	write_icr(icr);
}

/**
 * @description 定位 new 运算符。
 * @param {const uint64_t} size 分配大小。
 * @param {void* const} p 预分配内存。
 * @return {void*} 预分配内存指针。
 * @throws {无} 不抛出异常。
 * @example
 * auto* obj = new (buffer) xapic_t();
 */
void* apic_t::operator new(const uint64_t size, void* const p)
{
	// 业务说明：忽略 size，直接返回预分配地址。
	// 输入：size/p；输出：p；规则：定位 new；异常：不抛出。
	(void)size;

	return p;
}

/**
 * @description 定位 delete 运算符。
 * @param {void* const} p 释放地址。
 * @param {const uint64_t} size 释放大小。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * apic_t::operator delete(ptr, size);
 */
void apic_t::operator delete(void* const p, const uint64_t size)
{
#ifdef APIC_RUNTIME_INSTANCE_ALLOCATION
	// 业务说明：运行时分配模式下释放内存。
	// 输入：p/size；输出：内存释放；规则：调用外部分配器；异常：不抛出。
	free_memory(p, size);
#else
	// 业务说明：静态分配模式无需释放。
	// 输入：p/size；输出：无；规则：忽略；异常：不抛出。
	(void)p;
	(void)size;
#endif
}

/**
 * @description 初始化 xAPIC 实例。
 * @param {void} 无。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * xapic_t apic;
 */
xapic_t::xapic_t()
{
	// 业务说明：读取 APIC 基址并映射寄存器窗口。
	// 输入：无；输出：mapped_base_；规则：基址为 0 时不映射；异常：不抛出。
	const apic_base_t apic_base = read_apic_base();

	if (apic_base.flags != 0)
	{
		const uint64_t apic_physical_address = apic_base.apic_pfn << 12;

		mapped_base_ = static_cast<uint8_t*>(memory_manager::map_host_physical(apic_physical_address));
	}
}

/**
 * @description 读取 xAPIC 寄存器。
 * @param {const uint16_t} offset 寄存器偏移。
 * @return {uint32_t} 寄存器值。
 * @throws {无} 不抛出异常。
 * @example
 * auto value = apic.do_read(offset);
 */
uint32_t xapic_t::do_read(const uint16_t offset) const
{
	// 业务说明：从映射的 APIC 基址读取寄存器。
	// 输入：offset；输出：寄存器值；规则：未映射则返回 0；异常：不抛出。
	if (mapped_base_ == nullptr)
	{
		return 0;
	}

	return *reinterpret_cast<uint32_t*>(mapped_base_ + offset);
}

/**
 * @description 写入 xAPIC 寄存器。
 * @param {const uint16_t} offset 寄存器偏移。
 * @param {const uint32_t} value 写入值。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * apic.do_write(offset, value);
 */
void xapic_t::do_write(const uint16_t offset, const uint32_t value) const
{
	// 业务说明：向映射的 APIC 基址写入寄存器。
	// 输入：offset/value；输出：寄存器更新；规则：未映射则忽略；异常：不抛出。
	if (mapped_base_ != nullptr)
	{
		*reinterpret_cast<uint32_t*>(mapped_base_ + offset) = value;
	}
}

/**
 * @description 写入 xAPIC ICR 寄存器。
 * @param {const apic_full_icr_t} icr ICR 数据。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * apic.write_icr(icr);
 */
void xapic_t::write_icr(const apic_full_icr_t icr)
{
	// 业务说明：按 xAPIC 格式写入 ICR 低高双寄存器。
	// 输入：icr；输出：ICR 更新；规则：低高顺序写；异常：不抛出。
	constexpr uint16_t xapic_icr = apic::icr.xapic();

	do_write(xapic_icr, icr.low.flags);
	do_write(xapic_icr + 0x10, icr.high.flags);
}

/**
 * @description 设置 xAPIC ICR 目标字段。
 * @param {apic_full_icr_t&} icr ICR 数据。
 * @param {const uint32_t} destination 目标 APIC ID。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * apic.set_icr_longhand_destination(icr, apic_id);
 */
void xapic_t::set_icr_longhand_destination(apic_full_icr_t& icr, const uint32_t destination)
{
	// 业务说明：写入 xAPIC 目标字段。
	// 输入：icr/destination；输出：目标字段更新；规则：直接赋值；异常：不抛出。
	icr.high.xapic.destination_field = destination;
}

/**
 * @description 读取 x2APIC MSR。
 * @param {const uint32_t} msr MSR 编号。
 * @return {uint64_t} MSR 值。
 * @throws {无} 不抛出异常。
 * @example
 * auto value = apic.do_read(msr);
 */
uint64_t x2apic_t::do_read(const uint32_t msr)
{
	// 业务说明：通过 RDMSR 读取 x2APIC 寄存器。
	// 输入：msr；输出：寄存器值；规则：读取 MSR；异常：不抛出。
	return apic::intrin::rdmsr(msr);
}

/**
 * @description 写入 x2APIC MSR。
 * @param {const uint32_t} msr MSR 编号。
 * @param {const uint64_t} value 写入值。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * apic.do_write(msr, value);
 */
void x2apic_t::do_write(const uint32_t msr, const  uint64_t value)
{
	// 业务说明：通过 WRMSR 写入 x2APIC 寄存器。
	// 输入：msr/value；输出：寄存器更新；规则：写入 MSR；异常：不抛出。
	apic::intrin::wrmsr(msr, value);
}

/**
 * @description 写入 x2APIC ICR。
 * @param {const apic_full_icr_t} icr ICR 数据。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * apic.write_icr(icr);
 */
void x2apic_t::write_icr(const apic_full_icr_t icr)
{
	// 业务说明：将 ICR 全字段写入 x2APIC MSR。
	// 输入：icr；输出：ICR 更新；规则：单 MSR 写入；异常：不抛出。
	do_write(apic::icr.x2apic(), icr.flags);
}

/**
 * @description 设置 x2APIC ICR 目标字段。
 * @param {apic_full_icr_t&} icr ICR 数据。
 * @param {const uint32_t} destination 目标 APIC ID。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * apic.set_icr_longhand_destination(icr, apic_id);
 */
void x2apic_t::set_icr_longhand_destination(apic_full_icr_t& icr, const uint32_t destination)
{
	// 业务说明：写入 x2APIC 目标字段。
	// 输入：icr/destination；输出：目标字段更新；规则：直接赋值；异常：不抛出。
	icr.high.x2apic.destination_field = destination;
}

/**
 * @description APIC 基类写 ICR（占位）。
 * @param {const apic_full_icr_t} icr ICR 数据。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * apic->write_icr(icr);
 */
void apic_t::write_icr(const apic_full_icr_t icr)
{
	// 业务说明：基类占位实现，子类覆盖。
	// 输入：icr；输出：无；规则：不执行；异常：不抛出。
	(void)icr;
}

/**
 * @description APIC 基类设置目标字段（占位）。
 * @param {apic_full_icr_t&} icr ICR 数据。
 * @param {const uint32_t} destination 目标 APIC ID。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * apic->set_icr_longhand_destination(icr, apic_id);
 */
void apic_t::set_icr_longhand_destination(apic_full_icr_t& icr, const uint32_t destination)
{
	// 业务说明：基类占位实现，子类覆盖。
	// 输入：icr/destination；输出：无；规则：不执行；异常：不抛出。
	(void)icr;
	(void)destination;
}

/**
 * @description 创建 APIC 实例并选择 xAPIC/x2APIC 实现。
 * @param {void} 无。
 * @return {apic_t*} APIC 实例指针，失败返回 nullptr。
 * @throws {无} 不抛出异常。
 * @example
 * auto* apic = apic_t::create_instance();
 */
apic_t* apic_t::create_instance()
{
	// 业务说明：运行时分配 APIC 实例内存。
	// 输入：无；输出：apic_allocation；规则：由外部分配器提供；异常：不抛出。
#ifdef APIC_RUNTIME_INSTANCE_ALLOCATION
	void* apic_allocation = allocate_memory(needed_apic_class_instance_size);
#else
	// 业务说明：静态分配 APIC 实例内存，仅允许一次。
	// 输入：无；输出：apic_allocation；规则：重复调用返回 nullptr；异常：不抛出。
	static uint8_t has_used_allocation = 0;

	if (has_used_allocation != 0)
	{
		return nullptr;
	}

	has_used_allocation = 1;

	void* const apic_allocation = &apic_class_instance_allocation;
#endif

	// 业务说明：读取 APIC 基址并选择 x2APIC 模式。
	// 输入：无；输出：use_x2apic；规则：按启用状态与支持能力选择；异常：不抛出。
	const apic_base_t apic_base = read_apic_base();

	const uint8_t is_any_apic_enabled = is_any_enabled(apic_base);

	uint8_t use_x2apic;

	if (is_any_apic_enabled == 1)
	{
		use_x2apic = is_x2apic_enabled(apic_base);
	}
	else
	{
		use_x2apic = is_x2apic_supported();

		enable(use_x2apic);
	}

	apic_t* apic = nullptr;

	if (use_x2apic == 1)
	{
		apic = new (apic_allocation) x2apic_t();
	}
	else
	{
		apic = new (apic_allocation) xapic_t();
	}

	return apic;
}

