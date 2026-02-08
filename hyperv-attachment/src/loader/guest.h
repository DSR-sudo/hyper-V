#pragma once
// =============================================================================
// VMM Shadow Mapper - Guest Kernel Discovery
// Provides utilities for locating kernel modules in Guest address space
// =============================================================================

#include <cstdint>
#include <ia32-doc/ia32.hpp>

namespace loader {

// =============================================================================
// Guest Module Information
// =============================================================================

struct guest_module_info_t {
    uint64_t base_address;      // Guest virtual address
    uint32_t size_of_image;     // Size in bytes
    char     name[64];          // Module name (ASCII)
};

// =============================================================================
// Module Cache (for performance)
// =============================================================================

struct module_cache_t {
    uint64_t ntoskrnl_base;
    uint64_t hal_base;
    uint64_t netio_base;
    uint64_t fwpkclnt_base;
    uint64_t ndis_base;
    uint8_t  initialized;
};

// Global module cache
inline module_cache_t g_module_cache = {};

// =============================================================================
// Guest Context
// =============================================================================

// Set Guest CR3 for memory operations
void set_guest_cr3(cr3 guest_cr3);

// Set SLAT CR3 for host-to-guest translations
void set_slat_cr3(cr3 slat_cr3);

// Get current Guest CR3
cr3 get_guest_cr3();

// Get current SLAT CR3
cr3 get_slat_cr3();

// =============================================================================
// Kernel Discovery
// =============================================================================

// Initialize Guest kernel discovery
// Must be called before any module lookups
// @param ntoskrnl_base: Known base of ntoskrnl (if available), 0 to auto-detect
// @return: true if initialization succeeded
bool init_guest_discovery(uint64_t ntoskrnl_base = 0);

// Find a loaded kernel module by name
// @param module_name: Case-insensitive module name (e.g., "NETIO.SYS")
// @param out_info: Receives module information if found
// @return: true if found, false otherwise
bool find_guest_module(const char* module_name, guest_module_info_t* out_info);

// Get cached module base address
// @param module_name: Module name
// @return: Cached base address, or 0 if not cached
uint64_t get_cached_module_base(const char* module_name);

// =============================================================================
// PsLoadedModuleList Traversal
// =============================================================================

// Find ntoskrnl base by scanning Guest memory
// Uses MSR_LSTAR to locate KiSystemCall64, then walks backwards to find MZ
uint64_t find_ntoskrnl_via_lstar();

// Get PsLoadedModuleList address from ntoskrnl exports
uint64_t get_ps_loaded_module_list(uint64_t ntoskrnl_base);

// Enumerate all loaded modules
// @param callback: Called for each module, return false to stop enumeration
// @return: Number of modules enumerated
uint32_t enumerate_guest_modules(bool (*callback)(const guest_module_info_t* info, void* context), void* context);

} // namespace loader
