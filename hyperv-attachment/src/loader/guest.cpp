// =============================================================================
// VMM Shadow Mapper - Guest Kernel Discovery
// Provides utilities for locating kernel modules in Guest address space
// =============================================================================

#include "guest.h"
#include "pe.h"
#include "imports.h"
#include "../logs/logs.h"
#include "../crt/crt.h"
#include "../memory_manager/memory_manager.h"
#include "../arch/arch.h"
#include <intrin.h>

namespace loader {

// =============================================================================
// Internal State
// =============================================================================

namespace {
    cr3 g_guest_cr3 = {};
    cr3 g_slat_cr3 = {};
}

// =============================================================================
// Guest Context Management
// =============================================================================

void set_guest_cr3(cr3 guest_cr3) {
    g_guest_cr3 = guest_cr3;
}

void set_slat_cr3(cr3 slat_cr3) {
    g_slat_cr3 = slat_cr3;
}

cr3 get_guest_cr3() {
    return g_guest_cr3;
}

cr3 get_slat_cr3() {
    return g_slat_cr3;
}

// =============================================================================
// Memory Read Helper
// =============================================================================

static bool read_guest_memory(uint64_t guest_va, void* buffer, uint64_t size)
{
    if (g_slat_cr3.flags == 0 || g_guest_cr3.flags == 0) {
        return false;
    }

    const uint64_t bytes_read = memory_manager::operate_on_guest_virtual_memory(
        g_slat_cr3,
        buffer,
        guest_va,
        g_guest_cr3,
        size,
        memory_operation_t::read_operation
    );

    return bytes_read == size;
}

// =============================================================================
// ntoskrnl Detection via MSR_LSTAR
// =============================================================================

uint64_t find_ntoskrnl_via_lstar()
{
    // Read MSR_LSTAR which contains KiSystemCall64 address
    const uint64_t ki_system_call = __readmsr(0xC0000082);  // IA32_LSTAR
    
    if (ki_system_call == 0 || ki_system_call < 0xFFFF800000000000ULL) {
        logs::print("[Guest] MSR_LSTAR invalid: 0x%p\n", ki_system_call);
        return 0;
    }

    logs::print("[Guest] KiSystemCall64 at 0x%p\n", ki_system_call);

    // Walk backwards to find MZ header (page aligned)
    // ntoskrnl is typically aligned to 4KB or larger boundaries
    uint64_t search_base = ki_system_call & ~0xFFFULL;  // Page align down

    // Search up to 32MB backwards (ntoskrnl is large)
    constexpr uint64_t max_search = 32 * 1024 * 1024;
    const uint64_t min_address = (search_base > max_search) ? (search_base - max_search) : 0xFFFF800000000000ULL;

    uint16_t dos_magic = 0;

    for (uint64_t addr = search_base; addr >= min_address; addr -= 0x1000) {
        if (read_guest_memory(addr, &dos_magic, sizeof(dos_magic))) {
            if (dos_magic == IMAGE_DOS_SIGNATURE) {
                // Verify NT header
                int32_t e_lfanew = 0;
                if (read_guest_memory(addr + 0x3C, &e_lfanew, sizeof(e_lfanew))) {
                    if (e_lfanew > 0 && e_lfanew < 0x1000) {
                        uint32_t nt_sig = 0;
                        if (read_guest_memory(addr + e_lfanew, &nt_sig, sizeof(nt_sig))) {
                            if (nt_sig == IMAGE_NT_SIGNATURE) {
                                logs::print("[Guest] Found ntoskrnl at 0x%p\n", addr);
                                return addr;
                            }
                        }
                    }
                }
            }
        }
    }

    logs::print("[Guest] Failed to locate ntoskrnl\n");
    return 0;
}

// =============================================================================
// PsLoadedModuleList Access
// =============================================================================

// KLDR_DATA_TABLE_ENTRY (simplified, 64-bit)
#pragma pack(push, 1)
struct ldr_data_table_entry_t {
    uint64_t in_load_order_links_flink;     // LIST_ENTRY.Flink
    uint64_t in_load_order_links_blink;     // LIST_ENTRY.Blink
    uint64_t exception_table;
    uint64_t exception_table_size;
    uint64_t gp_value;
    uint64_t non_paged_debug_info;
    uint64_t dll_base;                       // Module base address
    uint64_t entry_point;
    uint32_t size_of_image;                  // Size of module
    uint32_t padding1;
    // UNICODE_STRING FullDllName
    uint16_t full_dll_name_length;
    uint16_t full_dll_name_max_length;
    uint32_t padding2;
    uint64_t full_dll_name_buffer;
    // UNICODE_STRING BaseDllName
    uint16_t base_dll_name_length;
    uint16_t base_dll_name_max_length;
    uint32_t padding3;
    uint64_t base_dll_name_buffer;
    // ... more fields follow
};
#pragma pack(pop)

uint64_t get_ps_loaded_module_list(uint64_t ntoskrnl_base)
{
    if (!ntoskrnl_base) {
        return 0;
    }

    // Find PsLoadedModuleList export
    return get_kernel_export(ntoskrnl_base, "PsLoadedModuleList");
}

// =============================================================================
// Module Enumeration
// =============================================================================

static bool wchar_to_ascii(uint64_t wchar_buffer, uint16_t length, char* out_ascii, uint32_t out_size)
{
    if (!wchar_buffer || length == 0 || !out_ascii || out_size == 0) {
        return false;
    }

    // Read wide characters (2 bytes each)
    const uint32_t char_count = length / 2;
    const uint32_t copy_count = (char_count < out_size - 1) ? char_count : out_size - 1;

    for (uint32_t i = 0; i < copy_count; i++) {
        uint16_t wchar = 0;
        if (!read_guest_memory(wchar_buffer + i * 2, &wchar, sizeof(wchar))) {
            out_ascii[i] = '?';
        } else {
            out_ascii[i] = static_cast<char>(wchar & 0xFF);
        }
    }
    out_ascii[copy_count] = '\0';

    return true;
}

uint32_t enumerate_guest_modules(bool (*callback)(const guest_module_info_t* info, void* context), void* context)
{
    if (!g_module_cache.ntoskrnl_base) {
        logs::print("[Guest] Cannot enumerate: ntoskrnl not found\n");
        return 0;
    }

    const uint64_t ps_loaded_list = get_ps_loaded_module_list(g_module_cache.ntoskrnl_base);
    if (!ps_loaded_list) {
        logs::print("[Guest] PsLoadedModuleList not found\n");
        return 0;
    }

    // Read list head (Flink)
    uint64_t list_head_flink = 0;
    if (!read_guest_memory(ps_loaded_list, &list_head_flink, sizeof(list_head_flink))) {
        logs::print("[Guest] Failed to read PsLoadedModuleList\n");
        return 0;
    }

    uint32_t module_count = 0;
    uint64_t current = list_head_flink;

    // Walk the doubly-linked list
    while (current != ps_loaded_list && module_count < 256) {
        ldr_data_table_entry_t entry = {};
        
        if (!read_guest_memory(current, &entry, sizeof(entry))) {
            break;
        }

        guest_module_info_t info = {};
        info.base_address = entry.dll_base;
        info.size_of_image = entry.size_of_image;

        // Read module name
        wchar_to_ascii(entry.base_dll_name_buffer, entry.base_dll_name_length, 
                      info.name, sizeof(info.name));

        if (callback && !callback(&info, context)) {
            break;
        }

        module_count++;
        current = entry.in_load_order_links_flink;
    }

    return module_count;
}

// =============================================================================
// Module Discovery
// =============================================================================

struct find_module_ctx_t {
    const char* search_name;
    guest_module_info_t* result;
    bool found;
};

static bool find_module_callback(const guest_module_info_t* info, void* context)
{
    auto* ctx = static_cast<find_module_ctx_t*>(context);

    if (str_compare_insensitive(info->name, ctx->search_name) == 0) {
        *ctx->result = *info;
        ctx->found = true;
        return false;  // Stop enumeration
    }

    return true;  // Continue
}

bool find_guest_module(const char* module_name, guest_module_info_t* out_info)
{
    if (!module_name || !out_info) {
        return false;
    }

    // Check cache first
    const uint64_t cached = get_cached_module_base(module_name);
    if (cached) {
        out_info->base_address = cached;
        out_info->size_of_image = 0;  // Unknown from cache
        // Copy name
        for (int i = 0; i < 63 && module_name[i]; i++) {
            out_info->name[i] = module_name[i];
            out_info->name[i + 1] = '\0';
        }
        return true;
    }

    // Search via PsLoadedModuleList
    find_module_ctx_t ctx = {
        .search_name = module_name,
        .result = out_info,
        .found = false
    };

    enumerate_guest_modules(find_module_callback, &ctx);

    // Update cache if found
    if (ctx.found) {
        if (str_compare_insensitive(module_name, "NETIO.SYS") == 0) {
            g_module_cache.netio_base = out_info->base_address;
        }
        else if (str_compare_insensitive(module_name, "HAL.dll") == 0) {
            g_module_cache.hal_base = out_info->base_address;
        }
        else if (str_compare_insensitive(module_name, "fwpkclnt.sys") == 0) {
            g_module_cache.fwpkclnt_base = out_info->base_address;
        }
        else if (str_compare_insensitive(module_name, "NDIS.SYS") == 0) {
            g_module_cache.ndis_base = out_info->base_address;
        }
    }

    return ctx.found;
}

uint64_t get_cached_module_base(const char* module_name)
{
    if (!module_name) return 0;

    if (str_compare_insensitive(module_name, "ntoskrnl.exe") == 0 ||
        str_compare_insensitive(module_name, "ntkrnlmp.exe") == 0) {
        return g_module_cache.ntoskrnl_base;
    }
    if (str_compare_insensitive(module_name, "HAL.dll") == 0) {
        return g_module_cache.hal_base;
    }
    if (str_compare_insensitive(module_name, "NETIO.SYS") == 0) {
        return g_module_cache.netio_base;
    }
    if (str_compare_insensitive(module_name, "fwpkclnt.sys") == 0) {
        return g_module_cache.fwpkclnt_base;
    }
    if (str_compare_insensitive(module_name, "NDIS.SYS") == 0) {
        return g_module_cache.ndis_base;
    }

    return 0;
}

// =============================================================================
// Initialization
// =============================================================================

bool init_guest_discovery(uint64_t ntoskrnl_base)
{
    if (g_module_cache.initialized) {
        return true;
    }

    // Set ntoskrnl base
    if (ntoskrnl_base) {
        g_module_cache.ntoskrnl_base = ntoskrnl_base;
    } else {
        // Auto-detect via MSR_LSTAR
        g_module_cache.ntoskrnl_base = find_ntoskrnl_via_lstar();
    }

    if (!g_module_cache.ntoskrnl_base) {
        logs::print("[Guest] Failed to initialize: ntoskrnl not found\n");
        return false;
    }

    logs::print("[Guest] Discovery initialized. ntoskrnl = 0x%p\n", g_module_cache.ntoskrnl_base);
    g_module_cache.initialized = 1;

    return true;
}

} // namespace loader
