#include "disk.h"
#include "../memory_manager/memory_manager.h"

#include <Library/UefiBootServicesTableLib.h>
#include <Library/DevicePathLib.h>

EFI_STATUS disk_get_all_file_system_handles(EFI_HANDLE** handle_list_out, UINT64* handle_count_out)
{
    EFI_GUID simple_fs_protocol_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;

    return gBS->LocateHandleBuffer(ByProtocol, &simple_fs_protocol_guid, NULL, handle_count_out, handle_list_out);
}

EFI_STATUS disk_open_file_system(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL** file_system_out, EFI_HANDLE handle)
{
    EFI_GUID simple_fs_protocol_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
    
    return gBS->HandleProtocol(handle, &simple_fs_protocol_guid, file_system_out);
}

EFI_STATUS disk_open_volume(EFI_FILE_PROTOCOL** volume_handle_out, EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* file_system)
{
    return file_system->OpenVolume(file_system, volume_handle_out);
}

EFI_STATUS disk_open_file_on_volume(EFI_FILE_PROTOCOL** file_handle_out, EFI_FILE_PROTOCOL* volume, CHAR16* file_path, UINT64 open_mode, UINT64 attributes)
{
    return volume->Open(volume, file_handle_out, file_path, open_mode, attributes);
}

EFI_STATUS disk_open_file(EFI_FILE_PROTOCOL** file_handle_out, EFI_HANDLE* file_system_handle_out_opt, CHAR16* file_path, UINT64 open_mode, UINT64 attributes)
{
    EFI_HANDLE* handle_list = NULL;
    UINT64 handle_count = 0;

    EFI_STATUS status = disk_get_all_file_system_handles(&handle_list, &handle_count);

    if (status != EFI_SUCCESS)
    {
        return status;
    }

    for (UINT64 i = 0; i < handle_count; i++)
    {
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* current_file_system = NULL;

        status = disk_open_file_system(&current_file_system, handle_list[i]);

        if (status != EFI_SUCCESS)
        {
            continue;
        }

        EFI_FILE_PROTOCOL* current_volume = NULL;

        status = disk_open_volume(&current_volume, current_file_system);

        if (status != EFI_SUCCESS)
        {
            continue;
        }

        status = disk_open_file_on_volume(file_handle_out, current_volume, file_path, open_mode, attributes);

        if (status == EFI_SUCCESS)
        {
            if (file_system_handle_out_opt != NULL)
            {
                *file_system_handle_out_opt = handle_list[i];
            }

            mm_free_pool(handle_list);

            return EFI_SUCCESS;
        }
    }

    mm_free_pool(handle_list);

    return EFI_NOT_FOUND;
}

EFI_STATUS disk_close_file(EFI_FILE_PROTOCOL* file_handle)
{
    return file_handle->Close(file_handle);
}

EFI_STATUS disk_read_file(EFI_FILE_PROTOCOL* file_handle, void* buffer, UINT64 size)
{
    return file_handle->Read(file_handle, &size, buffer);
}

EFI_STATUS disk_write_file(EFI_FILE_PROTOCOL* file_handle, void* buffer, UINT64 size)
{
    return file_handle->Write(file_handle, &size, buffer);
}

EFI_STATUS disk_delete_file(EFI_FILE_PROTOCOL* file_handle)
{
    return file_handle->Delete(file_handle);
}

EFI_STATUS disk_load_file(EFI_FILE_PROTOCOL* file_handle, void** buffer, UINT64 buffer_size)
{
    EFI_STATUS status = mm_allocate_pool(buffer, buffer_size, EfiBootServicesData);

    if (status != EFI_SUCCESS)
    {
        return status;
    }

    status = disk_read_file(file_handle, *buffer, buffer_size);

    if (status != EFI_SUCCESS)
    {
        mm_free_pool(*buffer);

        return status;
    }

    return EFI_SUCCESS;
}

EFI_STATUS disk_get_specified_type_file_info(void** buffer_out, UINT64* buffer_size_out, EFI_FILE_PROTOCOL* file_handle, EFI_GUID* information_type)
{
    EFI_STATUS status = file_handle->GetInfo(file_handle, information_type, buffer_size_out, NULL);

    if (status != EFI_BUFFER_TOO_SMALL)
    {
        return EFI_BAD_BUFFER_SIZE;
    }

    status = mm_allocate_pool(buffer_out, *buffer_size_out, EfiBootServicesData);

    if (status != EFI_SUCCESS)
    {
        return status;
    }

    status = file_handle->GetInfo(file_handle, information_type, buffer_size_out, *buffer_out);

    return status;
}

EFI_STATUS disk_get_generic_file_info(EFI_FILE_INFO** file_info_out, UINT64* file_info_size_out, EFI_FILE_PROTOCOL* file_handle)
{
    EFI_GUID information_type = EFI_FILE_INFO_ID;

    return disk_get_specified_type_file_info(file_info_out, file_info_size_out, file_handle, &information_type);
}

EFI_STATUS disk_set_specified_type_file_info(EFI_FILE_PROTOCOL* file_handle, EFI_GUID* information_type, void* buffer, UINT64 buffer_size)
{
    return file_handle->SetInfo(file_handle, information_type, buffer_size, buffer);
}

EFI_STATUS disk_set_generic_file_info(EFI_FILE_PROTOCOL* file_handle, EFI_FILE_INFO* file_info, UINT64 file_info_size)
{
    EFI_GUID information_type = EFI_FILE_INFO_ID;

    return disk_set_specified_type_file_info(file_handle, &information_type, file_info, file_info_size);
}

EFI_STATUS disk_get_device_path(EFI_DEVICE_PATH** device_path_out, EFI_HANDLE device_handle, CHAR16* file_path)
{
    *device_path_out = FileDevicePath(device_handle, file_path);

    return (*device_path_out != NULL) ? EFI_SUCCESS : EFI_OUT_OF_RESOURCES;
}
