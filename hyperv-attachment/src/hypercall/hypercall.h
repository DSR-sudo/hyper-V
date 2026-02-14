#pragma once
#include "../../shared/structures/trap_frame.h"

union hypercall_info_t;

namespace hypercall
{
	void process(hypercall_info_t hypercall_info, trap_frame_t* trap_frame);
}
