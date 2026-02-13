#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Guid/SmBios.h>

#include "bootmgfw/bootmgfw.h"
#include "hyperv_attachment/hyperv_attachment.h"
#include "memory_manager/memory_manager.h"

#ifndef SMBIOS3_TABLE_GUID
#define SMBIOS3_TABLE_GUID { 0xF2FD1544, 0x9794, 0x4A2C, { 0x99, 0x2E, 0xE5, 0xBB, 0xCF, 0x20, 0xE3, 0x94 } }
#endif

const UINT8 _gDriverUnloadImageCount = 1;
const UINT32 _gUefiDriverRevision = 0x200;
CHAR8* gEfiCallerBaseName = "hyper-reV";

static UINT32 cstr_len(const CHAR8* str)
{
    if (str == NULL)
    {
        return 0;
    }
    const CHAR8* current = str;
    while (*current != '\0')
    {
        current++;
    }
    return (UINT32)(current - str);
}

static UINT32 cstr_len_bounded(const CHAR8* str, const UINT8* end)
{
    if (str == NULL || end == NULL)
    {
        return 0;
    }
    const CHAR8* current = str;
    const CHAR8* limit = (const CHAR8*)end;
    while (current < limit && *current != '\0')
    {
        current++;
    }
    return (UINT32)(current - str);
}

static BOOLEAN match_bytes(const CHAR8* lhs, const CHAR8* rhs, UINT32 length)
{
    if (lhs == NULL || rhs == NULL)
    {
        return FALSE;
    }
    for (UINT32 i = 0; i < length; i++)
    {
        if (lhs[i] != rhs[i])
        {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOLEAN checksum_ok(const UINT8* data, UINT32 length)
{
    if (data == NULL || length == 0)
    {
        return FALSE;
    }
    UINT8 sum = 0;
    for (UINT32 i = 0; i < length; i++)
    {
        sum = (UINT8)(sum + data[i]);
    }
    return sum == 0;
}

#pragma pack(push, 1)
typedef struct _smbios_entry_point32
{
    CHAR8 anchor[4];
    UINT8 checksum;
    UINT8 length;
    UINT8 major;
    UINT8 minor;
    UINT16 max_structure_size;
    UINT8 entry_point_revision;
    UINT8 formatted_area[5];
    CHAR8 intermediate_anchor[5];
    UINT8 intermediate_checksum;
    UINT16 table_length;
    UINT32 table_address;
    UINT16 structure_count;
    UINT8 bcd_revision;
} smbios_entry_point32;

typedef struct _smbios_entry_point64
{
    CHAR8 anchor[5];
    UINT8 checksum;
    UINT8 length;
    UINT8 major;
    UINT8 minor;
    UINT8 docrev;
    UINT8 entry_point_revision;
    UINT8 reserved;
    UINT32 table_length;
    UINT64 table_address;
} smbios_entry_point64;

typedef struct _smbios_header
{
    UINT8 type;
    UINT8 length;
    UINT16 handle;
} smbios_header;
#pragma pack(pop)

static BOOLEAN find_smbios_table_from_config(UINT64* table_address_out, UINT32* table_length_out, BOOLEAN* is_64bit_out)
{
    if (table_address_out == NULL || table_length_out == NULL || is_64bit_out == NULL || gST == NULL)
    {
        return FALSE;
    }
    EFI_GUID smbios3_guid = SMBIOS3_TABLE_GUID;
    EFI_GUID smbios_guid = SMBIOS_TABLE_GUID;
    for (UINTN i = 0; i < gST->NumberOfTableEntries; i++)
    {
        EFI_CONFIGURATION_TABLE* config = &gST->ConfigurationTable[i];
        if (match_bytes((const CHAR8*)&config->VendorGuid, (const CHAR8*)&smbios3_guid, sizeof(EFI_GUID)))
        {
            smbios_entry_point64 entry64 = { 0 };
            if (config->VendorTable == NULL)
            {
                continue;
            }
            mm_copy_memory((UINT8*)&entry64, (const UINT8*)config->VendorTable, sizeof(entry64));
            if (match_bytes(entry64.anchor, "_SM3_", 5) && entry64.length >= sizeof(smbios_entry_point64) &&
                checksum_ok((const UINT8*)&entry64, entry64.length))
            {
                *table_address_out = entry64.table_address;
                *table_length_out = entry64.table_length;
                *is_64bit_out = TRUE;
                return TRUE;
            }
        }
        if (match_bytes((const CHAR8*)&config->VendorGuid, (const CHAR8*)&smbios_guid, sizeof(EFI_GUID)))
        {
            smbios_entry_point32 entry32 = { 0 };
            if (config->VendorTable == NULL)
            {
                continue;
            }
            mm_copy_memory((UINT8*)&entry32, (const UINT8*)config->VendorTable, sizeof(entry32));
            if (entry32.length >= 0x1F && match_bytes(entry32.anchor, "_SM_", 4) &&
                match_bytes(entry32.intermediate_anchor, "_DMI_", 5) &&
                checksum_ok((const UINT8*)&entry32, entry32.length) &&
                checksum_ok(((const UINT8*)&entry32) + (entry32.length - 0x0F), 0x0F))
            {
                *table_address_out = entry32.table_address;
                *table_length_out = entry32.table_length;
                *is_64bit_out = FALSE;
                return TRUE;
            }
        }
    }
    return FALSE;
}

static BOOLEAN overwrite_smbios_string(UINT8* structure, UINT8 string_index, const CHAR8* new_value, UINT8* table_end)
{
    if (structure == NULL || new_value == NULL || string_index == 0 || table_end == NULL)
    {
        return FALSE;
    }
    const smbios_header* header = (const smbios_header*)structure;
    UINT8* current = structure + header->length;
    for (UINT8 i = 1; i < string_index; i++)
    {
        if (current >= table_end)
        {
            return FALSE;
        }
        UINT32 len = cstr_len_bounded((const CHAR8*)current, table_end);
        current += len + 1;
    }
    if (current >= table_end)
    {
        return FALSE;
    }
    UINT32 original_len = cstr_len_bounded((const CHAR8*)current, table_end);
    UINT32 new_len = cstr_len(new_value);
    UINT32 copy_len = (original_len < new_len) ? original_len : new_len;
    if (copy_len > 0)
    {
        mm_copy_memory(current, (const UINT8*)new_value, copy_len);
    }
    if (copy_len < original_len)
    {
        mm_fill_memory(current + copy_len, original_len - copy_len, ' ');
    }
    return TRUE;
}

static void spoof_smbios_table(UINT8* table, UINT32 table_length)
{
    if (table == NULL || table_length == 0)
    {
        return;
    }
    UINT8* end = table + table_length;
    UINT8* current = table;
    const CHAR8* fixed_manufacturer = "DELL";
    const CHAR8* fixed_product_name = "Dell G16 6550";
    const CHAR8* fixed_serial_number = "465XC26";
    const CHAR8* fixed_memory_serial_1 = "43FBE46A";
    const CHAR8* fixed_memory_serial_2 = "43FBE46B";
    const CHAR8* fixed_memory_part = "SUM-asm-215";
    const UINT8 fixed_board_type = 0x0A;
    const UINT8 fixed_memory_type = 0x22;
    UINT8 memory_device_index = 0;
    while (current + sizeof(smbios_header) <= end)
    {
        smbios_header* header = (smbios_header*)current;
        if (header->type == 127 && header->length == 4)
        {
            break;
        }
        if (current + header->length > end)
        {
            break;
        }
        if (header->type == 1)
        {
            if (header->length >= 0x08)
            {
                overwrite_smbios_string(current, current[0x04], fixed_manufacturer, end);
                overwrite_smbios_string(current, current[0x05], fixed_product_name, end);
                overwrite_smbios_string(current, current[0x07], fixed_serial_number, end);
            }
            if (header->length >= 0x19)
            {
                const UINT8 fixed_uuid[16] = {
                    0x85, 0xF6, 0x43, 0x6B, 0x35, 0x00, 0x00, 0x31,
                    0x88, 0x54, 0xB4, 0xC0, 0x6F, 0x48, 0x83, 0x54
                };
                mm_copy_memory(current + 0x08, fixed_uuid, sizeof(fixed_uuid));
            }
        }
        else if (header->type == 2)
        {
            if (header->length > 0x04)
            {
                overwrite_smbios_string(current, current[0x04], fixed_manufacturer, end);
            }
            if (header->length > 0x05)
            {
                overwrite_smbios_string(current, current[0x05], fixed_product_name, end);
            }
            if (header->length > 0x07)
            {
                overwrite_smbios_string(current, current[0x07], fixed_serial_number, end);
            }
            if (header->length > 0x0D)
            {
                current[0x0D] = fixed_board_type;
            }
        }
        else if (header->type == 3)
        {
            if (header->length > 0x04)
            {
                overwrite_smbios_string(current, current[0x04], fixed_manufacturer, end);
            }
            if (header->length > 0x07)
            {
                overwrite_smbios_string(current, current[0x07], fixed_serial_number, end);
            }
        }
        else if (header->type == 17)
        {
            if (header->length >= 0x13)
            {
                current[0x12] = fixed_memory_type;
            }
            if (header->length >= 0x1B)
            {
                const CHAR8* serial_value = (memory_device_index % 2 == 0) ? fixed_memory_serial_1 : fixed_memory_serial_2;
                overwrite_smbios_string(current, current[0x17], fixed_manufacturer, end);
                overwrite_smbios_string(current, current[0x18], serial_value, end);
                overwrite_smbios_string(current, current[0x1A], fixed_memory_part, end);
                memory_device_index++;
            }
        }
        UINT8* next = current + header->length;
        while (next + 1 < end)
        {
            if (next[0] == 0 && next[1] == 0)
            {
                next += 2;
                break;
            }
            next++;
        }
        if (next <= current)
        {
            break;
        }
        current = next;
    }
}

static EFI_STATUS smbios_spoof()
{
    const UINT64 scan_start = 0xF0000;
    const UINT64 scan_end = 0x100000;
    UINT64 entry_physical = 0;
    smbios_entry_point32 entry32 = { 0 };
    smbios_entry_point64 entry64 = { 0 };
    BOOLEAN is_64bit = FALSE;
    UINT64 table_address = 0;
    UINT32 table_length = 0;
    if (!find_smbios_table_from_config(&table_address, &table_length, &is_64bit))
    {
        for (UINT64 address = scan_start; address + sizeof(smbios_entry_point64) <= scan_end; address += 0x10)
        {
            smbios_entry_point64* entry = (smbios_entry_point64*)(UINTN)address;
            mm_copy_memory((UINT8*)&entry64, (const UINT8*)entry, sizeof(entry64));
            if (match_bytes(entry64.anchor, "_SM3_", 5) && entry64.length >= sizeof(smbios_entry_point64) &&
                checksum_ok((const UINT8*)&entry64, entry64.length))
            {
                entry_physical = address;
                is_64bit = TRUE;
                break;
            }
        }
        if (entry_physical == 0)
        {
            for (UINT64 address = scan_start; address + sizeof(smbios_entry_point32) <= scan_end; address += 0x10)
            {
                smbios_entry_point32* entry = (smbios_entry_point32*)(UINTN)address;
                mm_copy_memory((UINT8*)&entry32, (const UINT8*)entry, sizeof(entry32));
                if (entry32.length >= 0x1F && match_bytes(entry32.anchor, "_SM_", 4) &&
                    match_bytes(entry32.intermediate_anchor, "_DMI_", 5) &&
                    checksum_ok((const UINT8*)&entry32, entry32.length) &&
                    checksum_ok(((const UINT8*)&entry32) + (entry32.length - 0x0F), 0x0F))
                {
                    entry_physical = address;
                    is_64bit = FALSE;
                    break;
                }
            }
        }
        if (entry_physical == 0)
        {
            return EFI_NOT_FOUND;
        }
        if (is_64bit)
        {
            table_address = entry64.table_address;
            table_length = entry64.table_length;
        }
        else
        {
            table_address = entry32.table_address;
            table_length = entry32.table_length;
        }
    }
    if (table_address == 0 || table_length == 0 || table_length > 0x20000)
    {
        return EFI_INVALID_PARAMETER;
    }
    UINT8* table = (UINT8*)(UINTN)table_address;
    spoof_smbios_table(table, table_length);
    return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
UefiUnload(
    IN EFI_HANDLE image_handle
)
{
    return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
UefiMain(
    IN EFI_HANDLE image_handle,
    IN EFI_SYSTEM_TABLE* system_table
)
{
    EFI_HANDLE device_handle = NULL;

    EFI_STATUS status = bootmgfw_restore_original_file(&device_handle);

    if (status != EFI_SUCCESS)
    {
        return status;
    }

    smbios_spoof();

    status = hyperv_attachment_set_up();

    if (status != EFI_SUCCESS)
    {
        return status;
    }

    return bootmgfw_run_original_image(image_handle, device_handle);
}
