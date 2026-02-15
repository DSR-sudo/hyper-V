#pragma once
#include <Library/ShellLib.h>

EFI_STATUS disk_get_all_file_system_handles(EFI_HANDLE** handle_list_out, UINT64* handle_count_out);
EFI_STATUS disk_open_file_system(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL** file_system_out, EFI_HANDLE handle);
EFI_STATUS disk_open_volume(EFI_FILE_PROTOCOL** volume_handle_out, EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* file_system);
EFI_STATUS disk_open_file_on_volume(EFI_FILE_PROTOCOL** file_handle_out, EFI_FILE_PROTOCOL* volume, CHAR16* file_path, UINT64 open_mode, UINT64 attributes);
EFI_STATUS disk_open_file(EFI_FILE_PROTOCOL** file_handle_out, EFI_HANDLE* device_handle_out_opt, CHAR16* file_path, UINT64 open_mode, UINT64 attributes);
EFI_STATUS disk_close_file(EFI_FILE_PROTOCOL* file_handle);
EFI_STATUS disk_read_file(EFI_FILE_PROTOCOL* file_handle, void* buffer, UINT64 size);
EFI_STATUS disk_write_file(EFI_FILE_PROTOCOL* file_handle, void* buffer, UINT64 size);
EFI_STATUS disk_delete_file(EFI_FILE_PROTOCOL* file_handle);
EFI_STATUS disk_load_file(EFI_FILE_PROTOCOL* file_handle, void** buffer, UINT64 buffer_size);
EFI_STATUS disk_get_specified_type_file_info(void** buffer_out, UINT64* buffer_size_out, EFI_FILE_PROTOCOL* file_handle, EFI_GUID* information_type);
EFI_STATUS disk_get_generic_file_info(EFI_FILE_INFO** file_info_out, UINT64* file_info_size_out, EFI_FILE_PROTOCOL* file_handle);
EFI_STATUS disk_set_specified_type_file_info(EFI_FILE_PROTOCOL* file_handle, EFI_GUID* information_type, void* buffer, UINT64 buffer_size);
EFI_STATUS disk_set_generic_file_info(EFI_FILE_PROTOCOL* file_handle, EFI_FILE_INFO* file_info, UINT64 file_info_size);
EFI_STATUS disk_get_device_path(EFI_DEVICE_PATH** device_path_out, EFI_HANDLE device_handle, CHAR16* file_path);
