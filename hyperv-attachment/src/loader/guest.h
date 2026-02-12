#pragma once
#include <cstdint>

namespace loader {

struct guest_module_info_t
{
    std::uint64_t base_address;
    std::uint32_t size;
};

bool find_guest_module(const char* module_name, std::uint64_t ntoskrnl_base, guest_module_info_t* out_info);

}
