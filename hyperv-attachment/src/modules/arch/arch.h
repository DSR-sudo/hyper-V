#pragma once
#include <ia32-doc/ia32.hpp>
#include <cstdint>

#include "amd_def.h"

namespace arch
{
	std::uint64_t get_vmexit_reason();
	std::uint8_t is_cpuid(std::uint64_t vmexit_reason);
	std::uint8_t is_slat_violation(std::uint64_t vmexit_reason);

	std::uint8_t is_non_maskable_interrupt_exit(std::uint64_t vmexit_reason);

	cr3 get_guest_cr3();
	std::uint8_t get_guest_cpl();

	cr3 get_slat_cr3();
	void set_slat_cr3(cr3 slat_cr3);

	void enable_mtf();
	void disable_mtf();
	std::uint8_t is_mtf_exit(std::uint64_t vmexit_reason);

	std::uint64_t get_guest_rsp();
	void set_guest_rsp(std::uint64_t guest_rsp);

	std::uint64_t get_guest_rip();
	void set_guest_rip(std::uint64_t guest_rip);

	std::uint64_t get_guest_rflags();
	void set_guest_rflags(std::uint64_t guest_rflags);

	std::uint64_t get_guest_cr8();
	std::uint64_t get_guest_idtr_base();
	std::uint64_t get_guest_lstar();

	void advance_guest_rip();


#ifdef _INTELMACHINE
	vmx_exit_qualification_ept_violation get_exit_qualification();

	std::uint64_t get_guest_physical_address();
#else
	vmcb_t* get_vmcb();
	void parse_vmcb_gadget(const std::uint8_t* get_vmcb_gadget);
#endif
}
