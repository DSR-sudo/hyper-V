#include "memory_manager.h"
#include <Library/UefiBootServicesTableLib.h>

#include <intrin.h>

cr0 read_cr0();
void write_cr0(cr0 value);
void disable_write_protection(cr0 original_cr0);

EFI_STATUS mm_allocate_pages(VOID** buffer_out, UINT64 page_count, EFI_MEMORY_TYPE memory_type)
{
	return gBS->AllocatePages(AllocateAnyPages, memory_type, page_count, (EFI_PHYSICAL_ADDRESS*)buffer_out);
}

EFI_STATUS mm_allocate_pool(VOID** buffer_out, UINT64 size, EFI_MEMORY_TYPE memory_type)
{
	return gBS->AllocatePool(memory_type, size, buffer_out);
}

EFI_STATUS mm_free_pool(VOID* buffer)
{
	return gBS->FreePool(buffer);
}

void mm_copy_memory(UINT8* destination, const UINT8* source, UINT64 size)
{
	cr0 original_cr0 = read_cr0();

	disable_write_protection(original_cr0);

	__movsb(destination, source, size);

	write_cr0(original_cr0);
}

void mm_fill_memory(UINT8* destination, UINT64 size, UINT8 value)
{
	cr0 original_cr0 = read_cr0();

	disable_write_protection(original_cr0);

	__stosb(destination, value, size);

	write_cr0(original_cr0);
}

cr0 read_cr0()
{
	cr0 value = { .flags = __readcr0() };

	return value;
}

void write_cr0(cr0 value)
{
	__writecr0(value.flags);
}

void disable_write_protection(cr0 original_cr0)
{
	cr0 new_cr0 = original_cr0;

	new_cr0.write_protect = 0;

	write_cr0(new_cr0);
}
