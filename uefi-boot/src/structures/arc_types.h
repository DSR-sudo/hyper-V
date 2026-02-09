#pragma once
#include <Library/UefiLib.h>

//
// ARC Types for Windows Boot Loader Structures
// Based on EfiGuard and Windows DDK headers
//
// NOTE: LIST_ENTRY is already defined by UEFI Base.h
// We only add PLIST_ENTRY pointer typedef if not already defined.
//

#ifndef PLIST_ENTRY
typedef LIST_ENTRY* PLIST_ENTRY;
#endif

//
// UNICODE_STRING - Unicode string descriptor
// Windows-style UNICODE_STRING for module name access
//
typedef struct _UNICODE_STRING_LDR {
    UINT16 Length;        // Length in bytes (not including null terminator)
    UINT16 MaximumLength; // Total buffer size in bytes
    CHAR16* Buffer;
} UNICODE_STRING_LDR, *PUNICODE_STRING_LDR;

//
// BASE_CR is already defined by UEFI Base.h
//

typedef struct _KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;          // +0x00
    VOID* ExceptionTable;                 // +0x10
    UINT32 ExceptionTableSize;            // +0x18
    VOID* GpValue;                        // +0x20
    struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo; // +0x28
    VOID* DllBase;                        // +0x30 - Image base address
    VOID* EntryPoint;                     // +0x38
    UINT32 SizeOfImage;                   // +0x40 - Image size
    UINT32 _Padding0;                     // +0x44
    UNICODE_STRING_LDR FullDllName;           // +0x48
    UNICODE_STRING_LDR BaseDllName;           // +0x58 - Module name (e.g., L"ntoskrnl.exe")
    // Remaining fields omitted for brevity
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

//
// BLDR_DATA_TABLE_ENTRY - Boot loader extended data table entry
// Wraps KLDR_DATA_TABLE_ENTRY with additional certificate info.
//
typedef struct _BLDR_DATA_TABLE_ENTRY {
    KLDR_DATA_TABLE_ENTRY KldrEntry;
    // Extended fields omitted
} BLDR_DATA_TABLE_ENTRY, *PBLDR_DATA_TABLE_ENTRY;

//
// LOADER_PARAMETER_BLOCK - Loader parameter block
// Passed to OslFwpKernelSetupPhase1 containing boot information.
// Windows 10/11 x64 layout (Build 17134+).
//
typedef struct _LOADER_PARAMETER_BLOCK {
    UINT32 OsMajorVersion;                // +0x00
    UINT32 OsMinorVersion;                // +0x04
    UINT32 Size;                          // +0x08
    UINT32 OsLoaderSecurityVersion;       // +0x0C
    LIST_ENTRY LoadOrderListHead;         // +0x10 - List of loaded modules (KLDR_DATA_TABLE_ENTRY)
    LIST_ENTRY MemoryDescriptorListHead;  // +0x20
    LIST_ENTRY BootDriverListHead;        // +0x30
    LIST_ENTRY EarlyLaunchListHead;       // +0x40
    LIST_ENTRY CoreDriverListHead;        // +0x50
    LIST_ENTRY CoreExtensionsDriverListHead; // +0x60
    LIST_ENTRY TpmCoreDriverListHead;     // +0x70
    // Remaining fields omitted for brevity
} LOADER_PARAMETER_BLOCK, *PLOADER_PARAMETER_BLOCK;

//
// String comparison helper (case-insensitive, limited length)
//
STATIC
inline
INT32
LdrStrniCmp(
    IN CONST CHAR16* Str1,
    IN CONST CHAR16* Str2,
    IN UINTN MaxLen
    )
{
    for (UINTN i = 0; i < MaxLen; i++)
    {
        CHAR16 c1 = Str1[i];
        CHAR16 c2 = Str2[i];

        // Simple case-insensitive comparison (ASCII range only)
        if (c1 >= L'A' && c1 <= L'Z') c1 += 32;
        if (c2 >= L'A' && c2 <= L'Z') c2 += 32;

        if (c1 != c2) return (INT32)(c1 - c2);
        if (c1 == L'\0') return 0;
    }
    return 0;
}

//
// GetBootLoadedModule - Find a module by name in the load order list
// Ported from EfiGuard.
// NOTE: The list entry IS the KLDR_DATA_TABLE_ENTRY (InLoadOrderLinks is first field)
//
STATIC
inline
PKLDR_DATA_TABLE_ENTRY
GetBootLoadedModule(
    IN CONST LIST_ENTRY* LoadOrderListHead,
    IN CONST CHAR16* ModuleName
    )
{
    if (ModuleName == NULL || LoadOrderListHead == NULL)
        return NULL;

    for (LIST_ENTRY* ListEntry = LoadOrderListHead->ForwardLink;
         ListEntry != LoadOrderListHead;
         ListEntry = ListEntry->ForwardLink)
    {
        // InLoadOrderLinks is the FIRST field of KLDR_DATA_TABLE_ENTRY
        // So the list entry pointer IS the KLDR_DATA_TABLE_ENTRY pointer
        PKLDR_DATA_TABLE_ENTRY Entry = (PKLDR_DATA_TABLE_ENTRY)ListEntry;
        
        if (Entry != NULL && Entry->BaseDllName.Buffer != NULL)
        {
            UINTN NameLen = Entry->BaseDllName.Length / sizeof(CHAR16);
            
            if (LdrStrniCmp(Entry->BaseDllName.Buffer, ModuleName, NameLen) == 0)
            {
                return Entry;
            }
        }
    }
    return NULL;
}
