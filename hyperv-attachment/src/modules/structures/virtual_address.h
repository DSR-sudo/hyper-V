#pragma once
#include <cstdint>

#pragma warning(push)
#pragma warning(disable: 4201)

union virtual_address_t
{
    std::uint64_t address;

    struct
    {
        std::uint64_t offset : 12;
        std::uint64_t pt_idx : 9;
        std::uint64_t pd_idx : 9;
        std::uint64_t pdpt_idx : 9;
        std::uint64_t pml4_idx : 9;
        std::uint64_t reserved : 16;
    };
};

#pragma warning(pop)
