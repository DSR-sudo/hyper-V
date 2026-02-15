#pragma once

typedef struct _relocation_entry_t
{
    UINT16 offset : 12;
    UINT16 type : 4;
} relocation_entry_t;
