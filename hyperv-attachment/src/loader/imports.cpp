// =============================================================================
// VMM Shadow Mapper - Import Resolver
// Ported from kdmapper::ResolveImports + intel_driver::GetKernelModuleExport
// =============================================================================

#include "imports.h"
#include "pe.h"
#include "guest.h"
#include "../logs/logs.h"
#include "../crt/crt.h"

namespace loader {

// =============================================================================
// String Utilities (No CRT)
// =============================================================================

int str_compare(const char* s1, const char* s2)
{
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *reinterpret_cast<const unsigned char*>(s1) - 
           *reinterpret_cast<const unsigned char*>(s2);
}

int str_compare_insensitive(const char* s1, const char* s2)
{
    while (*s1 && *s2) {
        char c1 = *s1;
        char c2 = *s2;
        
        // Convert to lowercase
        if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
        if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
        
        if (c1 != c2) {
            return c1 - c2;
        }
        s1++;
        s2++;
    }
    return *s1 - *s2;
}

// =============================================================================
// Export Table Resolution
// =============================================================================

uint64_t get_kernel_export(const uint64_t module_base, const char* function_name)
{
    if (!module_base || !function_name) {
        return 0;
    }

    // Get NT headers
    const auto dos_header = reinterpret_cast<image_dos_header_t*>(module_base);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    const auto nt_headers = reinterpret_cast<image_nt_headers64_t*>(
        module_base + dos_header->e_lfanew
    );
    if (nt_headers->signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    // Get export directory
    const auto& export_dir_entry = nt_headers->optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!export_dir_entry.virtual_address || !export_dir_entry.size) {
        return 0;
    }

    const auto export_dir = reinterpret_cast<image_export_directory_t*>(
        module_base + export_dir_entry.virtual_address
    );

    // Get export tables
    const auto name_table = reinterpret_cast<uint32_t*>(
        module_base + export_dir->address_of_names
    );
    const auto ordinal_table = reinterpret_cast<uint16_t*>(
        module_base + export_dir->address_of_name_ordinals
    );
    const auto function_table = reinterpret_cast<uint32_t*>(
        module_base + export_dir->address_of_functions
    );

    // Linear search through export names
    for (uint32_t i = 0; i < export_dir->number_of_names; ++i) {
        const char* current_name = reinterpret_cast<const char*>(
            module_base + name_table[i]
        );

        if (str_compare_insensitive(current_name, function_name) == 0) {
            const uint16_t ordinal = ordinal_table[i];
            const uint32_t function_rva = function_table[ordinal];

            // Check for forwarded export (RVA within export directory)
            if (function_rva >= export_dir_entry.virtual_address &&
                function_rva < export_dir_entry.virtual_address + export_dir_entry.size) {
                // Forwarded export - we don't handle these for now
                logs::print("[Loader] Warning: Forwarded export %s not supported\n", function_name);
                return 0;
            }

            return module_base + function_rva;
        }
    }

    return 0;
}

// =============================================================================
// Import Resolution
// =============================================================================

bool resolve_payload_imports(void* payload_image, const uint64_t ntoskrnl_base)
{
    if (!payload_image || !ntoskrnl_base) {
        logs::print("[Loader] resolve_imports: Invalid parameters\n");
        return false;
    }

    // Get NT headers
    const auto nt_headers = get_nt_headers(payload_image);
    if (!nt_headers) {
        logs::print("[Loader] resolve_imports: Invalid PE headers\n");
        return false;
    }

    // Get import directory
    const auto& import_dir = nt_headers->optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!import_dir.virtual_address) {
        // No imports - valid for some drivers
        logs::print("[Loader] resolve_imports: No import table\n");
        return true;
    }

    const uint64_t image_base = reinterpret_cast<uint64_t>(payload_image);

    // Walk import descriptors
    auto import_descriptor = reinterpret_cast<image_import_descriptor_t*>(
        image_base + import_dir.virtual_address
    );

    uint32_t modules_resolved = 0;
    uint32_t functions_resolved = 0;

    while (import_descriptor->first_thunk) {
        // Get module name
        const char* module_name = reinterpret_cast<const char*>(
            image_base + import_descriptor->name
        );

        logs::print("[Loader] Resolving imports from: %s\n", module_name);

        // Determine which module to search
        uint64_t resolve_module_base = 0;
        bool module_resolved = false;

        // Check for specific modules
        if (str_compare_insensitive(module_name, "ntoskrnl.exe") == 0 ||
            str_compare_insensitive(module_name, "ntkrnlmp.exe") == 0 ||
            str_compare_insensitive(module_name, "ntkrnlpa.exe") == 0 ||
            str_compare_insensitive(module_name, "ntkrpamp.exe") == 0) {
            resolve_module_base = ntoskrnl_base;
            module_resolved = true;
        }
        else if (str_compare_insensitive(module_name, "HAL.dll") == 0) {
            // Try to find HAL in loaded modules, fallback to ntoskrnl re-exports
            guest_module_info_t hal_info = {};
            if (find_guest_module("HAL.dll", &hal_info) && hal_info.base_address) {
                resolve_module_base = hal_info.base_address;
                logs::print("[Loader] HAL.dll found at 0x%p\n", resolve_module_base);
            } else {
                // HAL exports are often re-exported by ntoskrnl
                resolve_module_base = ntoskrnl_base;
                logs::print("[Loader] HAL.dll fallback to ntoskrnl re-exports\n");
            }
            module_resolved = true;
        }
        else if (str_compare_insensitive(module_name, "NETIO.SYS") == 0) {
            // CRITICAL: Must find actual NETIO.SYS - no fallback allowed
            guest_module_info_t netio_info = {};
            if (find_guest_module("NETIO.SYS", &netio_info) && netio_info.base_address) {
                resolve_module_base = netio_info.base_address;
                logs::print("[Loader] NETIO.SYS found at 0x%p\n", resolve_module_base);
                module_resolved = true;
            } else {
                logs::print("[Loader] ERROR: NETIO.SYS not found - cannot resolve imports\n");
                return false;
            }
        }
        else if (str_compare_insensitive(module_name, "fwpkclnt.sys") == 0) {
            // Firewall Platform Callout Kernel - required for network filtering
            guest_module_info_t fwp_info = {};
            if (find_guest_module("fwpkclnt.sys", &fwp_info) && fwp_info.base_address) {
                resolve_module_base = fwp_info.base_address;
                logs::print("[Loader] fwpkclnt.sys found at 0x%p\n", resolve_module_base);
                module_resolved = true;
            } else {
                logs::print("[Loader] ERROR: fwpkclnt.sys not found - cannot resolve imports\n");
                return false;
            }
        }
        else if (str_compare_insensitive(module_name, "NDIS.SYS") == 0) {
            guest_module_info_t ndis_info = {};
            if (find_guest_module("NDIS.SYS", &ndis_info) && ndis_info.base_address) {
                resolve_module_base = ndis_info.base_address;
                logs::print("[Loader] NDIS.SYS found at 0x%p\n", resolve_module_base);
                module_resolved = true;
            } else {
                logs::print("[Loader] ERROR: NDIS.SYS not found - cannot resolve imports\n");
                return false;
            }
        }
        else {
            // Unknown module - try to find it dynamically
            guest_module_info_t unknown_info = {};
            if (find_guest_module(module_name, &unknown_info) && unknown_info.base_address) {
                resolve_module_base = unknown_info.base_address;
                logs::print("[Loader] %s found at 0x%p\n", module_name, resolve_module_base);
                module_resolved = true;
            } else {
                logs::print("[Loader] ERROR: Unknown module %s not found\n", module_name);
                return false;
            }
        }

        // Get IAT and INT (or hint table)
        auto first_thunk = reinterpret_cast<image_thunk_data64_t*>(
            image_base + import_descriptor->first_thunk
        );
        
        auto original_first_thunk = import_descriptor->original_first_thunk
            ? reinterpret_cast<image_thunk_data64_t*>(image_base + import_descriptor->original_first_thunk)
            : first_thunk;

        // Walk thunks
        while (original_first_thunk->u1.address_of_data) {
            // Check if import by ordinal (high bit set)
            if (original_first_thunk->u1.ordinal & (1ULL << 63)) {
                logs::print("[Loader] Error: Import by ordinal not supported\n");
                return false;
            }

            // Import by name
            const auto import_by_name = reinterpret_cast<image_import_by_name_t*>(
                image_base + original_first_thunk->u1.address_of_data
            );

            const char* func_name = import_by_name->name;
            
            // Resolve the function
            uint64_t function_address = get_kernel_export(resolve_module_base, func_name);

            // If not found and we're not already using ntoskrnl, try ntoskrnl as last resort
            // (only for re-exported functions like HAL)
            if (!function_address && resolve_module_base != ntoskrnl_base) {
                // Only try ntoskrnl fallback for HAL (which has many re-exports)
                if (str_compare_insensitive(module_name, "HAL.dll") == 0) {
                    function_address = get_kernel_export(ntoskrnl_base, func_name);
                    if (function_address) {
                        logs::print("[Loader] %s resolved via ntoskrnl re-export\n", func_name);
                    }
                }
            }

            if (!function_address) {
                logs::print("[Loader] ERROR: Failed to resolve import: %s!%s\n", 
                    module_name, func_name);
                return false;
            }

            // Write resolved address to IAT
            first_thunk->u1.function = function_address;
            functions_resolved++;

            // Move to next thunk
            first_thunk++;
            original_first_thunk++;
        }

        modules_resolved++;
        import_descriptor++;
    }

    logs::print("[Loader] Resolved %d functions from %d modules\n", 
        functions_resolved, modules_resolved);
    
    return true;
}

} // namespace loader
