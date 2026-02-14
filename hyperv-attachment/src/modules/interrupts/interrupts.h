#pragma once
#include "../apic/apic.h"
#include "../crt/crt.h"

namespace interrupts
{
	struct context_t
	{
		apic_t* apic;
		crt::bitmap_t* nmi_ready_bitmap;
		std::uint64_t* original_nmi_handler_storage;
	};

	void set_up(context_t* ctx, apic_t* apic_instance, crt::bitmap_t* nmi_ready_bitmap, std::uint64_t* original_nmi_handler_storage);

	void set_all_nmi_ready(context_t* ctx);
	void set_nmi_ready(context_t* ctx, uint64_t apic_id);
	void clear_nmi_ready(context_t* ctx, uint64_t apic_id);

	crt::bitmap_t::bit_type is_nmi_ready(context_t* ctx, uint64_t apic_id);

	void process_nmi(context_t* ctx);
	void send_nmi_all_but_self(context_t* ctx);
}
