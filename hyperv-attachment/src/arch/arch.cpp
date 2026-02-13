#include "arch.h"
#include "../crt/crt.h"
#include "../memory_manager/heap_manager.h"
#include "../memory_manager/memory_manager.h"
#include <ia32-doc/ia32.hpp>
#include "../slat/cr3/cr3.h"

/**
 * @description 从 VMCS 读取字段值。
 * @param {const std::uint64_t} field VMCS 字段编号。
 * @return {std::uint64_t} 读取到的字段值。
 * @throws {无} 不抛出异常。
 * @example
 * const auto value = vmread(VMCS_EXIT_REASON);
 */
std::uint64_t vmread(const std::uint64_t field)
{
    // 业务说明：封装 VMREAD 指令读取 VMCS 字段。
    // 输入：field；输出：字段值；规则：由 VMX 指令返回；异常：不抛出。
    std::uint64_t value = 0;
    __vmx_vmread(field, &value);
    return value;
}

/**
 * @description 向 VMCS 写入字段值。
 * @param {const std::uint64_t} field VMCS 字段编号。
 * @param {const std::uint64_t} value 要写入的字段值。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * vmwrite(VMCS_GUEST_RIP, rip);
 */
void vmwrite(const std::uint64_t field, const std::uint64_t value)
{
    // 业务说明：封装 VMWRITE 指令更新 VMCS 字段。
    // 输入：field/value；输出：VMCS 更新；规则：由 VMX 指令执行；异常：不抛出。
    __vmx_vmwrite(field, value);
}

/**
 * @description 获取 VMExit 指令长度。
 * @param {void} 无。
 * @return {std::uint64_t} 指令长度。
 * @throws {无} 不抛出异常。
 * @example
 * const auto len = get_vmexit_instruction_length();
 */
std::uint64_t get_vmexit_instruction_length()
{
    // 业务说明：读取 VMExit 指令长度字段。
    // 输入：无；输出：指令长度；规则：读取 VMCS；异常：不抛出。
    return vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH);
}

/**
 * @description 读取 EPT 违规退出资格信息。
 * @param {void} 无。
 * @return {vmx_exit_qualification_ept_violation} 退出资格信息结构。
 * @throws {无} 不抛出异常。
 * @example
 * const auto qualification = arch::get_exit_qualification();
 */
vmx_exit_qualification_ept_violation arch::get_exit_qualification()
{
    // 业务说明：读取 VMCS 退出资格并解析为结构体。
    // 输入：无；输出：退出资格结构；规则：读取 VMCS；异常：不抛出。
    return { .flags = vmread(VMCS_EXIT_QUALIFICATION) };
}

/**
 * @description 获取当前 VMExit 的来宾物理地址。
 * @param {void} 无。
 * @return {std::uint64_t} 来宾物理地址。
 * @throws {无} 不抛出异常。
 * @example
 * const auto gpa = arch::get_guest_physical_address();
 */
std::uint64_t arch::get_guest_physical_address()
{
    // 业务说明：读取 VMCS 中的来宾物理地址字段。
    // 输入：无；输出：来宾物理地址；规则：读取 VMCS；异常：不抛出。
    return vmread(VMCS_GUEST_PHYSICAL_ADDRESS);
}

/**
 * @description 获取 VMExit 退出原因。
 * @param {void} 无。
 * @return {std::uint64_t} 退出原因编号。
 * @throws {无} 不抛出异常。
 * @example
 * const auto reason = arch::get_vmexit_reason();
 */
std::uint64_t arch::get_vmexit_reason()
{
    // 业务说明：读取 VMCS 退出原因字段。
    // 输入：无；输出：退出原因；规则：读取 VMCS；异常：不抛出。
    return vmread(VMCS_EXIT_REASON);
}

/**
 * @description 判断 VMExit 是否由 CPUID 指令触发。
 * @param {const std::uint64_t} vmexit_reason VMExit 退出原因。
 * @return {std::uint8_t} 是否为 CPUID 退出。
 * @throws {无} 不抛出异常。
 * @example
 * const auto is_cpuid_exit = arch::is_cpuid(reason);
 */
std::uint8_t arch::is_cpuid(const std::uint64_t vmexit_reason)
{
    // 业务说明：对比退出原因常量识别 CPUID 退出。
    // 输入：vmexit_reason；输出：判断结果；规则：等于常量则为真；异常：不抛出。
    return vmexit_reason == VMX_EXIT_REASON_EXECUTE_CPUID;
}

/**
 * @description 判断 VMExit 是否为 EPT 违规退出。
 * @param {const std::uint64_t} vmexit_reason VMExit 退出原因。
 * @return {std::uint8_t} 是否为 SLAT/EPT 违规退出。
 * @throws {无} 不抛出异常。
 * @example
 * const auto is_violation = arch::is_slat_violation(reason);
 */
std::uint8_t arch::is_slat_violation(const std::uint64_t vmexit_reason)
{
    // 业务说明：对比退出原因常量识别 EPT 违规。
    // 输入：vmexit_reason；输出：判断结果；规则：等于常量则为真；异常：不抛出。
    return vmexit_reason == VMX_EXIT_REASON_EPT_VIOLATION;
}

/**
 * @description 判断 VMExit 是否为 NMI 退出。
 * @param {const std::uint64_t} vmexit_reason VMExit 退出原因。
 * @return {std::uint8_t} 是否为 NMI 退出。
 * @throws {无} 不抛出异常。
 * @example
 * const auto is_nmi = arch::is_non_maskable_interrupt_exit(reason);
 */
std::uint8_t arch::is_non_maskable_interrupt_exit(const std::uint64_t vmexit_reason)
{
    // 业务说明：判断退出原因并解析中断信息类型。
    // 输入：vmexit_reason；输出：是否 NMI；规则：退出原因为异常/NMI 时才进一步解析；异常：不抛出。
    if (vmexit_reason != VMX_EXIT_REASON_EXCEPTION_OR_NMI)
    {
        return 0;
    }
    const std::uint64_t raw = vmread(VMCS_VMEXIT_INTERRUPTION_INFORMATION);
    const vmexit_interrupt_information info = { .flags = static_cast<std::uint32_t>(raw) };
    return info.interruption_type == interruption_type::non_maskable_interrupt;
}

/**
 * @description 获取当前来宾 CR3。
 * @param {void} 无。
 * @return {cr3} 来宾 CR3 结构。
 * @throws {无} 不抛出异常。
 * @example
 * const auto cr3_value = arch::get_guest_cr3();
 */
cr3 arch::get_guest_cr3()
{
    // 业务说明：读取来宾 CR3 字段并封装为结构体。
    // 输入：无；输出：CR3 结构；规则：读取 VMCS；异常：不抛出。
    cr3 guest_cr3;
    guest_cr3.flags = vmread(VMCS_GUEST_CR3);
    return guest_cr3;
}

/**
 * @description 获取当前 SLAT CR3。
 * @param {void} 无。
 * @return {cr3} SLAT CR3 结构。
 * @throws {无} 不抛出异常。
 * @example
 * const auto cr3_value = arch::get_slat_cr3();
 */
cr3 arch::get_slat_cr3()
{
    // 业务说明：读取 EPT 指针字段并封装为结构体。
    // 输入：无；输出：CR3 结构；规则：读取 VMCS；异常：不抛出。
    cr3 slat_cr3;
    slat_cr3.flags = vmread(VMCS_CTRL_EPT_POINTER);
    return slat_cr3;
}

/**
 * @description 设置 SLAT CR3。
 * @param {const cr3} slat_cr3 新的 SLAT CR3。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * arch::set_slat_cr3(cr3_value);
 */
void arch::set_slat_cr3(const cr3 slat_cr3)
{
    // 业务说明：写入 EPT 指针字段以切换 SLAT。
    // 输入：slat_cr3；输出：VMCS 更新；规则：写入 VMCS；异常：不抛出。
    vmwrite(VMCS_CTRL_EPT_POINTER, slat_cr3.flags);
}

/**
 * @description 启用 MTF（Monitor Trap Flag）。
 * @param {void} 无。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * arch::enable_mtf();
 */
void arch::enable_mtf()
{
    // 业务说明：打开处理器执行控制中的 MTF 位。
    // 输入：无；输出：控制位更新；规则：置位第 27 位；异常：不抛出。
    std::uint64_t controls = vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);
    controls |= (1ULL << 27); // Monitor Trap Flag (MTF)
    vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, controls);
}

/**
 * @description 关闭 MTF（Monitor Trap Flag）。
 * @param {void} 无。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * arch::disable_mtf();
 */
void arch::disable_mtf()
{
    // 业务说明：关闭处理器执行控制中的 MTF 位。
    // 输入：无；输出：控制位更新；规则：清除第 27 位；异常：不抛出。
    std::uint64_t controls = vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);
    controls &= ~(1ULL << 27);
    vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, controls);
}

/**
 * @description 判断 VMExit 是否为 MTF 退出。
 * @param {const std::uint64_t} vmexit_reason VMExit 退出原因。
 * @return {std::uint8_t} 是否为 MTF 退出。
 * @throws {无} 不抛出异常。
 * @example
 * const auto is_mtf = arch::is_mtf_exit(reason);
 */
std::uint8_t arch::is_mtf_exit(const std::uint64_t vmexit_reason)
{
    // 业务说明：对比退出原因常量识别 MTF 退出。
    // 输入：vmexit_reason；输出：判断结果；规则：等于常量则为真；异常：不抛出。
    return vmexit_reason == VMX_EXIT_REASON_MONITOR_TRAP_FLAG;
}

/**
 * @description 获取来宾 RSP。
 * @param {void} 无。
 * @return {std::uint64_t} 来宾 RSP。
 * @throws {无} 不抛出异常。
 * @example
 * const auto rsp = arch::get_guest_rsp();
 */
std::uint64_t arch::get_guest_rsp()
{
    // 业务说明：读取 VMCS 中的来宾 RSP。
    // 输入：无；输出：来宾 RSP；规则：读取 VMCS；异常：不抛出。
    return vmread(VMCS_GUEST_RSP);
}

/**
 * @description 设置来宾 RSP。
 * @param {const std::uint64_t} guest_rsp 新的来宾 RSP。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * arch::set_guest_rsp(rsp);
 */
void arch::set_guest_rsp(const std::uint64_t guest_rsp)
{
    // 业务说明：更新 VMCS 中的来宾 RSP。
    // 输入：guest_rsp；输出：VMCS 更新；规则：写入 VMCS；异常：不抛出。
    vmwrite(VMCS_GUEST_RSP, guest_rsp);
}

/**
 * @description 获取来宾 RIP。
 * @param {void} 无。
 * @return {std::uint64_t} 来宾 RIP。
 * @throws {无} 不抛出异常。
 * @example
 * const auto rip = arch::get_guest_rip();
 */
std::uint64_t arch::get_guest_rip()
{
    // 业务说明：读取 VMCS 中的来宾 RIP。
    // 输入：无；输出：来宾 RIP；规则：读取 VMCS；异常：不抛出。
    return vmread(VMCS_GUEST_RIP);
}

/**
 * @description 设置来宾 RIP。
 * @param {const std::uint64_t} guest_rip 新的来宾 RIP。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * arch::set_guest_rip(rip);
 */
void arch::set_guest_rip(const std::uint64_t guest_rip)
{
    // 业务说明：更新 VMCS 中的来宾 RIP。
    // 输入：guest_rip；输出：VMCS 更新；规则：写入 VMCS；异常：不抛出。
    vmwrite(VMCS_GUEST_RIP, guest_rip);
}

/**
 * @description 推进来宾 RIP 到下一条指令。
 * @param {void} 无。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * arch::advance_guest_rip();
 */
void arch::advance_guest_rip()
{
    // 业务说明：读取当前 RIP 与指令长度并推进到下一条指令。
    // 输入：无；输出：来宾 RIP 更新；规则：RIP += 指令长度；异常：不抛出。
    const std::uint64_t guest_rip = get_guest_rip();
    const std::uint64_t len = get_vmexit_instruction_length();
    set_guest_rip(guest_rip + len);
}
