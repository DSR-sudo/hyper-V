#pragma once
#include <Library/UefiLib.h>

// this image's info - will be zeroed by the hyperv-attachment
extern UINT64 uefi_boot_physical_base_address;
extern UINT32 uefi_boot_image_size;

typedef UINT64 unknown_param_t;
typedef UINT64(*boot_load_pe_image_t)(void* file_info, INT32 a2, UINT64* image_base, UINT32* image_size, UINT64* a5, UINT32* a6, UINT32* a7, UINT64 a8, UINT64 a9, unknown_param_t a10, unknown_param_t a11, unknown_param_t a12, unknown_param_t a13, unknown_param_t a14, unknown_param_t a15);

#define d_boot_load_pe_image_pattern "\x48\x89\x44\x24\x00\xE8\x00\x00\x00\x00\x8B\xD8\xEB\x00\xBB\x00\x00\x00\x00\x48\x8B"
#define d_boot_load_pe_image_mask "xxxx?x????xxx?x????xx"

EFI_STATUS bootmgfw_restore_original_file(EFI_HANDLE* device_handle_out);
EFI_STATUS bootmgfw_run_original_image(EFI_HANDLE parent_image_handle, EFI_HANDLE device_handle);
