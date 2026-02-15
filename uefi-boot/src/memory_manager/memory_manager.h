#pragma once
#include <Library/UefiLib.h>
#include <ia32-doc/ia32_compact.h>

EFI_STATUS mm_allocate_pages(VOID** buffer_out, UINT64 page_count, EFI_MEMORY_TYPE memory_type);
EFI_STATUS mm_allocate_pool(VOID** buffer_out, UINT64 size, EFI_MEMORY_TYPE memory_type);
EFI_STATUS mm_free_pool(VOID* buffer);
void mm_copy_memory(UINT8* destination, const UINT8* source, UINT64 size);
void mm_fill_memory(UINT8* destination, UINT64 size, UINT8 value);
