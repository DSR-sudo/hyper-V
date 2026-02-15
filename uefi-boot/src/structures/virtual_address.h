#pragma once

#pragma warning(push)
#pragma warning(disable: 4201)

typedef union _virtual_address_t
{
    UINT64 address;

    struct
    {
        UINT64 offset : 12;
        UINT64 pt_idx : 9;
        UINT64 pd_idx : 9;
        UINT64 pdpt_idx : 9;
        UINT64 pml4_idx : 9;
        UINT64 reserved : 16;
    };
} virtual_address_t;

#pragma warning(pop)
