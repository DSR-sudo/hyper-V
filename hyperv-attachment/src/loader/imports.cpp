// =============================================================================
// VMM Shadow Mapper - Import Resolver
// Ported from kdmapper::ResolveImports + intel_driver::GetKernelModuleExport
// =============================================================================

#include "imports.h"
#include "pe.h"
#include "guest.h"
#include "../logs/logs.h"
#include "../crt/crt.h"
#include "../arch/arch.h"
#include "../slat/cr3/cr3.h"
#include "../memory_manager/memory_manager.h"

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

struct unicode_string_t
{
    std::uint16_t length;
    std::uint16_t maximum_length;
    std::uint32_t padding;
    std::uint64_t buffer;
};

std::uint32_t ascii_length(const char* s)
{
    std::uint32_t length = 0;
    while (s && *s)
    {
        ++length;
        ++s;
    }
    return length;
}

bool wide_equals_ascii_insensitive(const std::uint16_t* wide, std::uint32_t wide_len, const char* ascii)
{
    if (!wide || !ascii)
    {
        return false;
    }

    const std::uint32_t ascii_len = ascii_length(ascii);
    if (ascii_len != wide_len)
    {
        return false;
    }

    for (std::uint32_t i = 0; i < wide_len; ++i)
    {
        std::uint16_t w = wide[i];
        char a = ascii[i];

        if (a >= 'A' && a <= 'Z')
        {
            a = static_cast<char>(a + 32);
        }

        if (w >= 'A' && w <= 'Z')
        {
            w = static_cast<std::uint16_t>(w + 32);
        }

        if (w != static_cast<std::uint16_t>(a))
        {
            return false;
        }
    }

    return true;
}

bool find_guest_module(const char* module_name, const std::uint64_t ntoskrnl_base, guest_module_info_t* out_info)
{
    if (!module_name || !out_info || !ntoskrnl_base)
    {
        return false;
    }

    out_info->base_address = 0;
    out_info->size = 0;

    const cr3 guest_cr3 = arch::get_guest_cr3();
    const cr3 slat_cr3 = slat::hyperv_cr3();

    auto read_guest = [&](uint64_t gva, void* buf, uint64_t size) -> bool {
        return memory_manager::operate_on_guest_virtual_memory(
            slat_cr3, buf, gva, guest_cr3, size, memory_operation_t::read_operation
        ) == size;
    };

    const std::uint64_t ps_loaded_module_list = get_kernel_export(ntoskrnl_base, "PsLoadedModuleList");
    if (!ps_loaded_module_list)
    {
        return false;
    }

    std::uint64_t current_entry = 0;
    if (!read_guest(ps_loaded_module_list, &current_entry, sizeof(current_entry)))
    {
        return false;
    }

    constexpr std::uint32_t max_iterations = 1024;
    for (std::uint32_t i = 0; i < max_iterations && current_entry && current_entry != ps_loaded_module_list; ++i)
    {
        std::uint64_t next_entry = 0;
        if (!read_guest(current_entry, &next_entry, sizeof(next_entry)))
        {
            break;
        }

        std::uint64_t module_base_address = 0;
        std::uint32_t module_size = 0;
        unicode_string_t module_name_unicode = {};

        read_guest(current_entry + 0x30, &module_base_address, sizeof(module_base_address));
        read_guest(current_entry + 0x40, &module_size, sizeof(module_size));
        read_guest(current_entry + 0x58, &module_name_unicode, sizeof(module_name_unicode));

        if (module_base_address && module_name_unicode.length && module_name_unicode.buffer)
        {
            std::uint16_t name_buffer[260] = {};
            const std::uint32_t max_bytes = static_cast<std::uint32_t>(sizeof(name_buffer) - sizeof(std::uint16_t));
            const std::uint32_t bytes_to_read = crt::min<std::uint32_t>(module_name_unicode.length, max_bytes);

            if (bytes_to_read > 0 &&
                read_guest(module_name_unicode.buffer, name_buffer, bytes_to_read))
            {
                const std::uint32_t char_count = bytes_to_read / sizeof(std::uint16_t);
                name_buffer[char_count] = 0;

                if (wide_equals_ascii_insensitive(name_buffer, char_count, module_name))
                {
                    out_info->base_address = module_base_address;
                    out_info->size = module_size;
                    return true;
                }
            }
        }

        current_entry = next_entry;
    }

    return false;
}

// =============================================================================
// Export Table Resolution (Secure Guest Access)
// =============================================================================

uint64_t get_kernel_export(const uint64_t module_base, const char* function_name)
{
    if (!module_base || !function_name) {
        return 0;
    }

    // Capture current Guest context
    const cr3 guest_cr3 = arch::get_guest_cr3();
    const cr3 slat_cr3 = slat::hyperv_cr3();

    // Helper: read from Guest virtual memory
    auto read_guest = [&](uint64_t gva, void* buf, uint64_t size) -> bool {
        return memory_manager::operate_on_guest_virtual_memory(
            slat_cr3, buf, gva, guest_cr3, size, memory_operation_t::read_operation
        ) == size;
    };

    // 1. Read DOS Header
    image_dos_header_t dos_header;
    if (!read_guest(module_base, &dos_header, sizeof(dos_header)) || 
        dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    // 2. Read NT Headers
    image_nt_headers64_t nt_headers;
    if (!read_guest(module_base + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers)) ||
        nt_headers.signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    // 3. Get Export Directory RVA and Size
    const auto& export_dir_entry = nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (export_dir_entry.virtual_address == 0 || export_dir_entry.size == 0) {
        return 0;
    }

    // 4. Read Export Directory
    image_export_directory_t export_dir;
    if (!read_guest(module_base + export_dir_entry.virtual_address, &export_dir, sizeof(export_dir))) {
        return 0;
    }

    // 5. Read Export Tables
    // Local buffers for table addresses
    const uint64_t names_va = module_base + export_dir.address_of_names;
    const uint64_t ordinals_va = module_base + export_dir.address_of_name_ordinals;
    const uint64_t functions_va = module_base + export_dir.address_of_functions;

    for (uint32_t i = 0; i < export_dir.number_of_names; ++i) {
        uint32_t name_rva = 0;
        if (!read_guest(names_va + i * sizeof(uint32_t), &name_rva, sizeof(uint32_t))) {
            continue;
        }

        // Read export name string (max 256 chars for safety)
        char current_name[256] = { 0 };
        if (!read_guest(module_base + name_rva, current_name, sizeof(current_name) - 1)) {
            continue;
        }

        if (str_compare_insensitive(current_name, function_name) == 0) {
            uint16_t ordinal = 0;
            if (!read_guest(ordinals_va + i * sizeof(uint16_t), &ordinal, sizeof(uint16_t))) {
                return 0;
            }

            uint32_t function_rva = 0;
            if (!read_guest(functions_va + ordinal * sizeof(uint32_t), &function_rva, sizeof(uint32_t))) {
                return 0;
            }

            // Check for forwarded export (RVA within export directory range)
            if (function_rva >= export_dir_entry.virtual_address &&
                function_rva < export_dir_entry.virtual_address + export_dir_entry.size) {
                logs::print("[Loader] Warning: Forwarded export '%s' not supported\n", function_name);
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
            if (find_guest_module("HAL.dll", ntoskrnl_base, &hal_info) && hal_info.base_address) {
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
            if (find_guest_module("NETIO.SYS", ntoskrnl_base, &netio_info) && netio_info.base_address) {
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
            if (find_guest_module("fwpkclnt.sys", ntoskrnl_base, &fwp_info) && fwp_info.base_address) {
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
            if (find_guest_module("NDIS.SYS", ntoskrnl_base, &ndis_info) && ndis_info.base_address) {
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
            if (find_guest_module(module_name, ntoskrnl_base, &unknown_info) && unknown_info.base_address) {
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
