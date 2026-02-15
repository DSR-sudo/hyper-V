#pragma once
#include <Library/UefiLib.h>

typedef union _parted_address_t
{
	struct
	{
		UINT32 low_part;
		UINT32 high_part;
	} u;

	UINT64 value;
} parted_address_t;

typedef struct _hook_data_t
{
	VOID* hooked_subroutine_address;
	UINT8 hook_bytes[14];
	UINT8 original_bytes[14];
} hook_data_t;

EFI_STATUS hook_create(hook_data_t* hook_data_out, void* subroutine_to_hook, void* subroutine_to_jmp_to);
EFI_STATUS hook_enable(hook_data_t* hook_data);
EFI_STATUS hook_disable(hook_data_t* hook_data);
