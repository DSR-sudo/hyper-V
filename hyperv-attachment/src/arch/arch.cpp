#include "arch.h"
#include "../crt/crt.h"
#include "../memory_manager/memory_manager.h"
#include "../memory_manager/heap_manager.h"
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

void arch::enable_mtf()
{
    std::uint64_t controls = vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);
    controls |= (1ULL << 27); // Monitor Trap Flag (MTF)
    vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, controls);
}

void arch::disable_mtf()
{
    std::uint64_t controls = vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);
    controls &= ~(1ULL << 27);
    vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, controls);
}

std::uint8_t arch::is_mtf_exit(const std::uint64_t vmexit_reason)
{
    return vmexit_reason == VMX_EXIT_REASON_MONITOR_TRAP_FLAG;
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

std::uint64_t arch::get_guest_lstar(bool* out_is_from_list)
{
    if (out_is_from_list) *out_is_from_list = false;

    // 1. Primary Method: VMCS Field 0x2816 (Guest IA32_LSTAR).
    // Reference: Intel SDM Vol 3C, Appendix B.
    std::uint64_t lstar = vmread(0x00002816);
    if (lstar != 0)
    {
        return lstar;
    }

    // 2. Fallback: Scan VM-exit MSR-store list.
    // Some processors/VMMs store Guest MSRs in a dedicated memory area.
    const std::uint64_t msr_store_addr = vmread(VMCS_CTRL_VMEXIT_MSR_STORE_ADDRESS);
    const std::uint32_t msr_store_count = static_cast<std::uint32_t>(vmread(VMCS_CTRL_VMEXIT_MSR_STORE_COUNT));

    if (msr_store_addr != 0 && msr_store_count != 0 && msr_store_count < 512)
    {
        struct vmx_msr_entry_t {
            std::uint32_t index;
            std::uint32_t reserved;
            std::uint64_t value;
        };

        const auto entries = static_cast<const vmx_msr_entry_t*>(memory_manager::map_host_physical(msr_store_addr));
        if (entries)
        {
            for (std::uint32_t i = 0; i < msr_store_count; i++)
            {
                if (entries[i].index == 0xC0000082) // IA32_LSTAR
                {
                    if (out_is_from_list) *out_is_from_list = true;
                    return entries[i].value;
                }
            }
        }
    }

    return 0;
}

std::uint64_t arch::get_guest_gs_base()
{
    // VMCS Field 0x681A is Guest IA32_GS_BASE.
    // Reference: Intel SDM Vol 3C, Appendix B.
    return vmread(0x0000681A);
}
