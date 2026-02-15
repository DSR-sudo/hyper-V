#include "image.h"
#include <Library/UefiBootServicesTableLib.h>

EFI_STATUS load_image(EFI_HANDLE* loaded_image_handle_out, BOOLEAN boot_policy, EFI_HANDLE parent_image_handle, EFI_DEVICE_PATH* device_path)
{
    return gBS->LoadImage(boot_policy, parent_image_handle, device_path, NULL, 0, loaded_image_handle_out);
}

EFI_STATUS unload_image(EFI_HANDLE image_handle)
{
    return gBS->UnloadImage(image_handle);
}

EFI_STATUS start_image(EFI_HANDLE image_handle)
{
    return gBS->StartImage(image_handle, NULL, NULL);
}

EFI_STATUS get_image_info(EFI_LOADED_IMAGE** image_info_out, EFI_HANDLE image_handle)
{
    EFI_GUID loaded_image_protocol_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID;

    return gBS->HandleProtocol(image_handle, &loaded_image_protocol_guid, image_info_out);
}

EFI_STATUS scan_image(CHAR8** location_out, CHAR8* scan_base, UINT64 scan_max_size, UINT8* pattern, UINT8* mask)
{
    if (location_out == NULL || scan_base == NULL || scan_max_size == 0 || pattern == NULL || mask == NULL)
    {
        return EFI_INVALID_PARAMETER;
    }

    UINT64 mask_size = AsciiStrLen(mask);

    CHAR8* scan_limit = scan_base + scan_max_size - mask_size;

    for (CHAR8* current_byte = scan_base; current_byte <= scan_limit; current_byte++)
    {
        BOOLEAN was_pattern_found = 1;

        for (UINT64 i = 0; i < mask_size; i++)
        {
            CHAR8 current_mask_byte = mask[i];

            if (current_mask_byte == '?')
            {
                continue;
            }

            CHAR8 current_pattern_byte = pattern[i];

            if (current_pattern_byte != current_byte[i])
            {
                was_pattern_found = 0;

                break;
            }
        }

        if (was_pattern_found == 1)
        {
            *location_out = current_byte;

            return EFI_SUCCESS;
        }
    }

    return EFI_NOT_FOUND;
}

EFI_IMAGE_NT_HEADERS64* image_get_nt_headers(UINT8* image_base)
{
    EFI_IMAGE_DOS_HEADER* dos_header = (EFI_IMAGE_DOS_HEADER*)image_base;

    EFI_IMAGE_NT_HEADERS64* nt_headers = (EFI_IMAGE_NT_HEADERS64*)(image_base + dos_header->e_lfanew);

    return nt_headers;
}
