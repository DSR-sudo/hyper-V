#pragma once
#include <Library/UefiLib.h>
#include <IndustryStandard/PeImage.h>

extern UINT8* hyperv_attachment_file_buffer;

extern UINT64 hyperv_attachment_heap_allocation_base;
extern UINT64 hyperv_attachment_heap_allocation_usable_base;
extern UINT64 hyperv_attachment_heap_allocation_size;
extern UINT32 hyperv_attachment_heap_4kb_pages_reserved;

EFI_STATUS hyperv_attachment_set_up();
UINT64 hyperv_attachment_get_pages_needed();
EFI_STATUS hyperv_attachment_do_heap_allocation(void** allocation_base_out, UINT64 pages_needed);
EFI_STATUS hyperv_attachment_allocate_and_copy(UINT64 pages_needed);
EFI_STATUS hyperv_attachment_get_relocated_entry_point(UINT8** hyperv_attachment_entry_point);
void hyperv_attachment_invoke_entry_point(UINT8** hyperv_attachment_vmexit_handler_detour_out, UINT8* hyperv_attachment_entry_point, CHAR8* original_vmexit_handler, UINT64 heap_physical_base, UINT64 heap_physical_usable_base, UINT64 heap_total_size, UINT64 uefi_boot_physical_base_address, UINT32 uefi_boot_image_size, CHAR8* get_vmcb_gadget, UINT64 ntoskrnl_base);
EFI_STATUS hyperv_attachment_load_and_delete_from_disk(UINT8** file_buffer_out);

