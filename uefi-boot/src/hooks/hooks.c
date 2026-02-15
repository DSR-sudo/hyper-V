#include "hooks.h"
#include "../memory_manager/memory_manager.h"

EFI_STATUS hook_create(hook_data_t* hook_data_out, void* subroutine_to_hook, void* subroutine_to_jmp_to)
{
	if (hook_data_out == NULL || subroutine_to_hook == NULL || subroutine_to_jmp_to == NULL)
	{
		return EFI_INVALID_PARAMETER;
	}

	UINT8 hook_bytes[14] = {
		0x68, 0x21, 0x43, 0x65, 0x87, // push   0xffffffff87654321
		0xC7, 0x44, 0x24, 0x04, 0x78, 0x56, 0x34, 0x12, // mov    DWORD PTR [rsp+0x4],0x12345678
		0xC3 // ret
	};

	parted_address_t parted_subroutine_to_jmp_to = { .value = (UINT64)subroutine_to_jmp_to };

	*(UINT32*)(&hook_bytes[1]) = parted_subroutine_to_jmp_to.u.low_part;
	*(UINT32*)(&hook_bytes[9]) = parted_subroutine_to_jmp_to.u.high_part;

	mm_copy_memory(hook_data_out->original_bytes, subroutine_to_hook, sizeof(hook_bytes));
	mm_copy_memory(hook_data_out->hook_bytes, hook_bytes, sizeof(hook_bytes));

	hook_data_out->hooked_subroutine_address = subroutine_to_hook;

	return EFI_SUCCESS;
}

EFI_STATUS hook_enable(hook_data_t* hook_data)
{
	if (hook_data == NULL)
	{
		return EFI_INVALID_PARAMETER;
	}

	mm_copy_memory(hook_data->hooked_subroutine_address, hook_data->hook_bytes, 14);

	return EFI_SUCCESS;
}

EFI_STATUS hook_disable(hook_data_t* hook_data)
{
	if (hook_data == NULL)
	{
		return EFI_INVALID_PARAMETER;
	}

	mm_copy_memory(hook_data->hooked_subroutine_address, hook_data->original_bytes, 14);

	return EFI_SUCCESS;
}
