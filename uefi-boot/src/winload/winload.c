#include "winload.h"
#include "../hooks/hooks.h"
#include "../image/image.h"
#include "../bootmgfw/bootmgfw.h"
#include "../structures/ntdef.h"
#include "../structures/arc_types.h"
#include "../hvloader/hvloader.h"

UINT64 pml4_physical_allocation = 0;
UINT64 pdpt_physical_allocation = 0;

// Task 1.4: Captured kernel base address (from LoaderBlock)
UINT64 g_captured_ntoskrnl_base = 0;
UINT32 g_captured_ntoskrnl_size = 0;

hook_data_t winload_load_pe_image_hook_data = { 0 };
hook_data_t osl_kernel_setup_hook_data = { 0 };

typedef EFI_STATUS (EFIAPI *t_OslFwpKernelSetupPhase1)(PLOADER_PARAMETER_BLOCK LoaderBlock);

// Backup for original function bytes
UINT8 g_osl_kernel_setup_backup[14] = { 0 };
t_OslFwpKernelSetupPhase1 g_original_osl_kernel_setup = NULL;

//
// EfiGuard-style signature for OslFwpKernelSetupPhase1 (Windows 10 RS4+)
// Pattern bytes where 0xCC = wildcard
//
STATIC CONST UINT8 SigOslFwpKernelSetupPhase1[] = {
    0x89, 0xCC, 0x24, 0x01, 0x00, 0x00,  // mov [REG+124h], r32
    0xE8, 0xCC, 0xCC, 0xCC, 0xCC,        // call BlBdStop
    0xCC, 0x8B, 0xCC                     // mov r32, r/m32
};

//
// PE Image structures for exception directory parsing
//
typedef struct _IMAGE_DOS_HEADER {
    UINT16 e_magic;    // MZ
    UINT16 e_cblp;
    UINT16 e_cp;
    UINT16 e_crlc;
    UINT16 e_cparhdr;
    UINT16 e_minalloc;
    UINT16 e_maxalloc;
    UINT16 e_ss;
    UINT16 e_sp;
    UINT16 e_csum;
    UINT16 e_ip;
    UINT16 e_cs;
    UINT16 e_lfarlc;
    UINT16 e_ovno;
    UINT16 e_res[4];
    UINT16 e_oemid;
    UINT16 e_oeminfo;
    UINT16 e_res2[10];
    UINT32 e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    UINT16 Machine;
    UINT16 NumberOfSections;
    UINT32 TimeDateStamp;
    UINT32 PointerToSymbolTable;
    UINT32 NumberOfSymbols;
    UINT16 SizeOfOptionalHeader;
    UINT16 Characteristics;
} IMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    UINT32 VirtualAddress;
    UINT32 Size;
} IMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    UINT16 Magic;
    UINT8 MajorLinkerVersion;
    UINT8 MinorLinkerVersion;
    UINT32 SizeOfCode;
    UINT32 SizeOfInitializedData;
    UINT32 SizeOfUninitializedData;
    UINT32 AddressOfEntryPoint;
    UINT32 BaseOfCode;
    UINT64 ImageBase;
    UINT32 SectionAlignment;
    UINT32 FileAlignment;
    UINT16 MajorOperatingSystemVersion;
    UINT16 MinorOperatingSystemVersion;
    UINT16 MajorImageVersion;
    UINT16 MinorImageVersion;
    UINT16 MajorSubsystemVersion;
    UINT16 MinorSubsystemVersion;
    UINT32 Win32VersionValue;
    UINT32 SizeOfImage;
    UINT32 SizeOfHeaders;
    UINT32 CheckSum;
    UINT16 Subsystem;
    UINT16 DllCharacteristics;
    UINT64 SizeOfStackReserve;
    UINT64 SizeOfStackCommit;
    UINT64 SizeOfHeapReserve;
    UINT64 SizeOfHeapCommit;
    UINT32 LoaderFlags;
    UINT32 NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    UINT32 Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64;

typedef struct _IMAGE_SECTION_HEADER {
    UINT8 Name[8];
    UINT32 VirtualSize;
    UINT32 VirtualAddress;
    UINT32 SizeOfRawData;
    UINT32 PointerToRawData;
    UINT32 PointerToRelocations;
    UINT32 PointerToLinenumbers;
    UINT16 NumberOfRelocations;
    UINT16 NumberOfLinenumbers;
    UINT32 Characteristics;
} IMAGE_SECTION_HEADER;

typedef struct _RUNTIME_FUNCTION {
    UINT32 BeginAddress;
    UINT32 EndAddress;
    UINT32 UnwindData;
} RUNTIME_FUNCTION;

#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3

//
// EfiGuard-style FindPattern: uses 0xCC as wildcard
//
STATIC
EFI_STATUS
FindPatternEx(
    IN CONST UINT8* Pattern,
    IN UINT8 Wildcard,
    IN UINT32 PatternLength,
    IN CONST VOID* Base,
    IN UINT32 Size,
    OUT VOID** Found
    )
{
    if (Found == NULL || Pattern == NULL || Base == NULL)
        return EFI_INVALID_PARAMETER;

    *Found = NULL;

    for (UINT8* Address = (UINT8*)Base; Address < (UINT8*)((UINTN)Base + Size - PatternLength); ++Address)
    {
        UINT32 i;
        for (i = 0; i < PatternLength; ++i)
        {
            if (Pattern[i] != Wildcard && (*(Address + i) != Pattern[i]))
                break;
        }

        if (i == PatternLength)
        {
            *Found = (VOID*)Address;
            return EFI_SUCCESS;
        }
    }

    return EFI_NOT_FOUND;
}

//
// EfiGuard-style FindFunctionStart: uses PE exception directory (RUNTIME_FUNCTION)
// This is much more robust than simple prologue scanning
//
STATIC
UINT8*
FindFunctionStartPE(
    IN CONST UINT8* ImageBase,
    IN CONST UINT8* AddressInFunction
    )
{
    if (AddressInFunction == NULL || ImageBase == NULL)
        return NULL;

    // Get PE headers
    CONST IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)ImageBase;
    if (DosHeader->e_magic != 0x5A4D)
        return NULL;

    CONST IMAGE_NT_HEADERS64* NtHeaders = (IMAGE_NT_HEADERS64*)(ImageBase + DosHeader->e_lfanew);
    if (NtHeaders->Signature != 0x00004550)
        return NULL;

    if (NtHeaders->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXCEPTION)
        return NULL;

    // Get exception directory (RUNTIME_FUNCTION table)
    CONST UINT32 ExceptionRva = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    CONST UINT32 ExceptionSize = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;

    if (ExceptionRva == 0 || ExceptionSize == 0)
        return NULL;

    CONST RUNTIME_FUNCTION* FunctionTable = (RUNTIME_FUNCTION*)(ImageBase + ExceptionRva);
    CONST UINT32 FunctionCount = ExceptionSize / sizeof(RUNTIME_FUNCTION);

    // Binary search for the function containing our address
    CONST UINT32 RelativeAddress = (UINT32)(AddressInFunction - ImageBase);
    INT32 Low = 0;
    INT32 High = (INT32)FunctionCount - 1;

    while (High >= Low)
    {
        INT32 Middle = (Low + High) >> 1;
        CONST RUNTIME_FUNCTION* Entry = &FunctionTable[Middle];

        if (RelativeAddress < Entry->BeginAddress)
            High = Middle - 1;
        else if (RelativeAddress >= Entry->EndAddress)
            Low = Middle + 1;
        else
        {
            // Found the function entry
            return (UINT8*)(ImageBase + Entry->BeginAddress);
        }
    }

    return NULL;
}

//
// Task 1.4: OslFwpKernelSetupPhase1 hook detour
// Extracts ntoskrnl.exe base from LoaderBlock->LoadOrderListHead
// NOTE: DO NOT use Print() here - UEFI console is unavailable at this boot stage!
//
EFI_STATUS EFIAPI hooked_osl_kernel_setup_phase1(PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    // 1. Restore original bytes FIRST (hook is one-shot)
    hook_disable(&osl_kernel_setup_hook_data);

    // 2. Find ntoskrnl.exe in LoadOrderListHead
    if (LoaderBlock != NULL)
    {
        PKLDR_DATA_TABLE_ENTRY KernelEntry = GetBootLoadedModule(
            &LoaderBlock->LoadOrderListHead,
            L"ntoskrnl.exe"
        );

        if (KernelEntry != NULL && KernelEntry->DllBase != NULL)
        {
            g_captured_ntoskrnl_base = (UINT64)KernelEntry->DllBase;
            g_captured_ntoskrnl_size = KernelEntry->SizeOfImage;
            // Success - base address captured (no Print - would hang!)
        }
    }

    // 3. Call original function to continue boot
    return g_original_osl_kernel_setup(LoaderBlock);
}

//
// Task 1.4: Place OslFwpKernelSetupPhase1 hook
// Uses EfiGuard's proven logic: FindPattern with 0xCC wildcard + PE exception directory
//
EFI_STATUS winload_place_kernel_setup_hook(UINT64 image_base, UINT64 image_size)
{
    VOID* sig_match = NULL;

    // Get .text section bounds from PE headers
    CONST IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)image_base;
    if (DosHeader->e_magic != 0x5A4D)
    {
        Print(L"[Task 1.4] Invalid DOS header\n");
        return EFI_LOAD_ERROR;
    }

    CONST IMAGE_NT_HEADERS64* NtHeaders = (IMAGE_NT_HEADERS64*)(image_base + DosHeader->e_lfanew);
    if (NtHeaders->Signature != 0x00004550)
    {
        Print(L"[Task 1.4] Invalid PE signature\n");
        return EFI_LOAD_ERROR;
    }

    // Get first section (.text)
    CONST IMAGE_SECTION_HEADER* TextSection = (IMAGE_SECTION_HEADER*)((UINT8*)&NtHeaders->OptionalHeader + NtHeaders->FileHeader.SizeOfOptionalHeader);
    CONST UINT8* TextStart = (UINT8*)(image_base + TextSection->VirtualAddress);
    CONST UINT32 TextSize = TextSection->SizeOfRawData;

    Print(L"[Task 1.4] winload.efi .text: 0x%lx, size: 0x%x\n", (UINT64)TextStart, TextSize);

    // Search for the signature (0xCC = wildcard)
    EFI_STATUS status = FindPatternEx(
        SigOslFwpKernelSetupPhase1,
        0xCC,  // Wildcard byte
        sizeof(SigOslFwpKernelSetupPhase1),
        TextStart,
        TextSize,
        &sig_match
    );

    if (status != EFI_SUCCESS)
    {
        Print(L"[Task 1.4] Signature not found in winload.efi\n");
        return status;
    }

    Print(L"[Task 1.4] Signature found at 0x%lx\n", (UINT64)sig_match);

    // Backtrack to function start using PE exception directory
    UINT8* function_start = FindFunctionStartPE((UINT8*)image_base, (UINT8*)sig_match);

    if (function_start == NULL)
    {
        Print(L"[Task 1.4] Failed to find function start via RUNTIME_FUNCTION\n");
        return EFI_NOT_FOUND;
    }

    Print(L"[Task 1.4] OslFwpKernelSetupPhase1 at 0x%lx\n", (UINT64)function_start);

    g_original_osl_kernel_setup = (t_OslFwpKernelSetupPhase1)function_start;

    status = hook_create(&osl_kernel_setup_hook_data, (CHAR8*)function_start, (void*)hooked_osl_kernel_setup_phase1);

    if (status != EFI_SUCCESS)
    {
        Print(L"[Task 1.4] hook_create failed: 0x%lx\n", status);
        return status;
    }

    status = hook_enable(&osl_kernel_setup_hook_data);
    if (status == EFI_SUCCESS)
    {
        Print(L"[Task 1.4] OslFwpKernelSetupPhase1 hook enabled!\n");
    }

    return status;
}

UINT64 winload_load_pe_image_detour(bl_file_info_t* file_info, INT32 a2, UINT64* image_base, UINT32* image_size, UINT64* a5, UINT32* a6, UINT32* a7, UINT64 a8, UINT64 a9, unknown_param_t a10, unknown_param_t a11, unknown_param_t a12, unknown_param_t a13, unknown_param_t a14, unknown_param_t a15)
{
    hook_disable(&winload_load_pe_image_hook_data);

    boot_load_pe_image_t original_subroutine = (boot_load_pe_image_t)winload_load_pe_image_hook_data.hooked_subroutine_address;

    UINT64 return_value = original_subroutine(file_info, a2, image_base, image_size, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15);

    if (StrStr(file_info->file_name, L"hvloader") != NULL)
    {
        hvloader_place_hooks(*image_base, *image_size);

        return return_value;
    }

    hook_enable(&winload_load_pe_image_hook_data);

    return return_value;
}

EFI_STATUS winload_place_load_pe_image_hook(UINT64 image_base, UINT64 image_size)
{
    CHAR8* code_ref_to_load_pe_image = NULL;

    // ImgpLoadPEImage
    EFI_STATUS status = scan_image(&code_ref_to_load_pe_image, (CHAR8*)image_base, image_size, d_boot_load_pe_image_pattern, d_boot_load_pe_image_mask);

    if (status != EFI_SUCCESS)
    {
        return status;
    }

    CHAR8* load_pe_image_subroutine = (code_ref_to_load_pe_image + 10) + *(UINT32*)(code_ref_to_load_pe_image + 6);

    status = hook_create(&winload_load_pe_image_hook_data, load_pe_image_subroutine, (void*)winload_load_pe_image_detour);

    if (status != EFI_SUCCESS)
    {
        return status;
    }

    return hook_enable(&winload_load_pe_image_hook_data);
}

EFI_STATUS winload_place_hooks(UINT64 image_base, UINT64 image_size)
{
    // Task 1.4: Place kernel setup hook first
    EFI_STATUS status = winload_place_kernel_setup_hook(image_base, image_size);
    
    if (status != EFI_SUCCESS)
    {
        Print(L"[Task 1.4] WARNING: OslFwpKernelSetupPhase1 hook failed: 0x%lx\n", status);
        // Continue anyway - fallback probing is still available
    }

    return winload_place_load_pe_image_hook(image_base, image_size);
}
