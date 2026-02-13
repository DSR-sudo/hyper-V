#pragma once
#include <cstdint>

struct trap_frame_t;

namespace business::driver_instrumentation {
std::uint64_t request_prepare();
std::uint64_t request_trigger();
void on_first_vmexit(std::uint64_t ntoskrnl_base);
bool on_vmexit(std::uint64_t exit_reason, trap_frame_t *trap_frame);
} // namespace business::driver_instrumentation
