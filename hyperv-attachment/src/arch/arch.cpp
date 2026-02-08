#include "arch.h"
#include "../crt/crt.h"
#include <intrin.h>
#include <ia32-doc/ia32.hpp>

std::uint64_t vmread(const std::uint64_t field)
{
    std::uint64_t value = 0;
    __vmx_vmread(field, &value);
    return value;
}

void vmwrite(const std::uint64_t field, const std::uint64_t value)
{
    __vmx_vmwrite(field, value);
}

std::uint64_t get_vmexit_instruction_length()
{
    return vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH);
}

vmx_exit_qualification_ept_violation arch::get_exit_qualification()
{
    return { .flags = vmread(VMCS_EXIT_QUALIFICATION) };
}

std::uint64_t arch::get_guest_physical_address()
{
    return vmread(VMCS_GUEST_PHYSICAL_ADDRESS);
}

std::uint64_t arch::get_vmexit_reason()
{
    return vmread(VMCS_EXIT_REASON);
}

std::uint8_t arch::is_cpuid(const std::uint64_t vmexit_reason)
{
    return vmexit_reason == VMX_EXIT_REASON_EXECUTE_CPUID;
}

std::uint8_t arch::is_slat_violation(const std::uint64_t vmexit_reason)
{
    return vmexit_reason == VMX_EXIT_REASON_EPT_VIOLATION;
}

std::uint8_t arch::is_non_maskable_interrupt_exit(const std::uint64_t vmexit_reason)
{
    if (vmexit_reason != VMX_EXIT_REASON_EXCEPTION_OR_NMI) return 0;
    const std::uint64_t raw = vmread(VMCS_VMEXIT_INTERRUPTION_INFORMATION);
    const vmexit_interrupt_information info = { .flags = static_cast<std::uint32_t>(raw) };
    return info.interruption_type == interruption_type::non_maskable_interrupt;
}

cr3 arch::get_guest_cr3()
{
    cr3 guest_cr3;
    guest_cr3.flags = vmread(VMCS_GUEST_CR3);
    return guest_cr3;
}

cr3 arch::get_slat_cr3()
{
    cr3 slat_cr3;
    slat_cr3.flags = vmread(VMCS_CTRL_EPT_POINTER);
    return slat_cr3;
}

void arch::set_slat_cr3(const cr3 slat_cr3)
{
    vmwrite(VMCS_CTRL_EPT_POINTER, slat_cr3.flags);
}

std::uint64_t arch::get_guest_rsp() { return vmread(VMCS_GUEST_RSP); }
void arch::set_guest_rsp(const std::uint64_t guest_rsp) { vmwrite(VMCS_GUEST_RSP, guest_rsp); }

std::uint64_t arch::get_guest_rip() { return vmread(VMCS_GUEST_RIP); }
void arch::set_guest_rip(const std::uint64_t guest_rip) { vmwrite(VMCS_GUEST_RIP, guest_rip); }

void arch::advance_guest_rip()
{
    const std::uint64_t guest_rip = get_guest_rip();
    const std::uint64_t len = get_vmexit_instruction_length();
    set_guest_rip(guest_rip + len);
}
