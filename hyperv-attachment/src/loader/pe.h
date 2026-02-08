#pragma once
// =============================================================================
// VMM Shadow Mapper - PE Structure Definitions
// Ported from kdmapper/portable_executable.hpp without STL dependencies
// =============================================================================

#include <cstdint>

namespace loader {

// =============================================================================
// DOS/NT/PE Constants
// =============================================================================
constexpr uint16_t IMAGE_DOS_SIGNATURE = 0x5A4D;      // MZ
constexpr uint32_t IMAGE_NT_SIGNATURE = 0x00004550;   // PE\0\0
constexpr uint16_t IMAGE_FILE_MACHINE_AMD64 = 0x8664;
constexpr uint16_t IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B;

// Relocation types
constexpr uint16_t IMAGE_REL_BASED_ABSOLUTE = 0;
constexpr uint16_t IMAGE_REL_BASED_DIR64 = 10;

// Directory entries
constexpr uint32_t IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
constexpr uint32_t IMAGE_DIRECTORY_ENTRY_IMPORT = 1;
constexpr uint32_t IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;
constexpr uint32_t IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10;
constexpr uint32_t IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;

// Default security cookie value (used before initialization)
constexpr uint64_t DEFAULT_SECURITY_COOKIE = 0x00002B992DDFA232ULL;

// =============================================================================
// PE Header Structures
// =============================================================================

#pragma pack(push, 1)

struct image_dos_header_t {
    uint16_t e_magic;      // Magic number (MZ)
    uint16_t e_cblp;       // Bytes on last page of file
    uint16_t e_cp;         // Pages in file
    uint16_t e_crlc;       // Relocations
    uint16_t e_cparhdr;    // Size of header in paragraphs
    uint16_t e_minalloc;   // Minimum extra paragraphs needed
    uint16_t e_maxalloc;   // Maximum extra paragraphs needed
    uint16_t e_ss;         // Initial (relative) SS value
    uint16_t e_sp;         // Initial SP value
    uint16_t e_csum;       // Checksum
    uint16_t e_ip;         // Initial IP value
    uint16_t e_cs;         // Initial (relative) CS value
    uint16_t e_lfarlc;     // File address of relocation table
    uint16_t e_ovno;       // Overlay number
    uint16_t e_res[4];     // Reserved words
    uint16_t e_oemid;      // OEM identifier
    uint16_t e_oeminfo;    // OEM information
    uint16_t e_res2[10];   // Reserved words
    int32_t  e_lfanew;     // File address of new exe header
};

struct image_file_header_t {
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t time_date_stamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
};

struct image_data_directory_t {
    uint32_t virtual_address;
    uint32_t size;
};

struct image_optional_header64_t {
    uint16_t magic;
    uint8_t  major_linker_version;
    uint8_t  minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
    uint64_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_operating_system_version;
    uint16_t minor_operating_system_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t check_sum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint64_t size_of_stack_reserve;
    uint64_t size_of_stack_commit;
    uint64_t size_of_heap_reserve;
    uint64_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
    image_data_directory_t data_directory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

struct image_nt_headers64_t {
    uint32_t signature;
    image_file_header_t file_header;
    image_optional_header64_t optional_header;
};

struct image_section_header_t {
    uint8_t  name[8];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t size_of_raw_data;
    uint32_t pointer_to_raw_data;
    uint32_t pointer_to_relocations;
    uint32_t pointer_to_linenumbers;
    uint16_t number_of_relocations;
    uint16_t number_of_linenumbers;
    uint32_t characteristics;
};

// =============================================================================
// Base Relocation Structures
// =============================================================================

struct image_base_relocation_t {
    uint32_t virtual_address;
    uint32_t size_of_block;
    // Following this is an array of uint16_t entries
};

// =============================================================================
// Import Structures
// =============================================================================

struct image_import_descriptor_t {
    union {
        uint32_t characteristics;
        uint32_t original_first_thunk;  // RVA to INT
    };
    uint32_t time_date_stamp;
    uint32_t forwarder_chain;
    uint32_t name;                      // RVA to module name
    uint32_t first_thunk;               // RVA to IAT
};

struct image_thunk_data64_t {
    union {
        uint64_t forwarder_string;
        uint64_t function;
        uint64_t ordinal;
        uint64_t address_of_data;       // RVA to IMAGE_IMPORT_BY_NAME
    } u1;
};

struct image_import_by_name_t {
    uint16_t hint;
    char     name[1];  // Variable length
};

// =============================================================================
// Export Structures
// =============================================================================

struct image_export_directory_t {
    uint32_t characteristics;
    uint32_t time_date_stamp;
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t name;
    uint32_t base;
    uint32_t number_of_functions;
    uint32_t number_of_names;
    uint32_t address_of_functions;      // RVA to function addresses
    uint32_t address_of_names;          // RVA to name strings
    uint32_t address_of_name_ordinals;  // RVA to ordinals
};

// =============================================================================
// Load Config (for Security Cookie)
// =============================================================================

struct image_load_config_directory64_t {
    uint32_t size;
    uint32_t time_date_stamp;
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t global_flags_clear;
    uint32_t global_flags_set;
    uint32_t critical_section_default_timeout;
    uint64_t de_commit_free_block_threshold;
    uint64_t de_commit_total_free_threshold;
    uint64_t lock_prefix_table;
    uint64_t maximum_allocation_size;
    uint64_t virtual_memory_threshold;
    uint64_t process_affinity_mask;
    uint32_t process_heap_flags;
    uint16_t csd_version;
    uint16_t dependent_load_flags;
    uint64_t edit_list;
    uint64_t security_cookie;           // Pointer to security cookie
    uint64_t se_handler_table;
    uint64_t se_handler_count;
    // ... additional fields omitted for brevity
};

#pragma pack(pop)

// =============================================================================
// Loader Internal Structures (No STL)
// =============================================================================

struct reloc_info_t {
    uint64_t  address;      // Base address for this reloc block
    uint16_t* item;         // Pointer to reloc entries
    uint32_t  count;        // Number of entries
};

struct import_function_info_t {
    const char* name;       // Function name
    uint64_t*   address;    // Pointer to IAT slot
};

struct import_info_t {
    const char*            module_name;  // DLL/module name
    import_function_info_t* functions;   // Array of functions
    uint32_t               count;        // Number of functions
};

// =============================================================================
// PE Parsing Helper Functions
// =============================================================================

inline image_dos_header_t* get_dos_header(void* image_base) {
    return reinterpret_cast<image_dos_header_t*>(image_base);
}

inline image_nt_headers64_t* get_nt_headers(void* image_base) {
    const auto dos_header = get_dos_header(image_base);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        return nullptr;
    }
    
    const auto nt_headers = reinterpret_cast<image_nt_headers64_t*>(
        reinterpret_cast<uint8_t*>(image_base) + dos_header->e_lfanew
    );
    
    if (nt_headers->signature != IMAGE_NT_SIGNATURE) {
        return nullptr;
    }
    
    return nt_headers;
}

inline image_section_header_t* get_first_section(image_nt_headers64_t* nt_headers) {
    return reinterpret_cast<image_section_header_t*>(
        reinterpret_cast<uint8_t*>(&nt_headers->optional_header) + 
        nt_headers->file_header.size_of_optional_header
    );
}

inline uint64_t get_image_base(void* image) {
    const auto nt = get_nt_headers(image);
    return nt ? nt->optional_header.image_base : 0;
}

inline uint32_t get_size_of_image(void* image) {
    const auto nt = get_nt_headers(image);
    return nt ? nt->optional_header.size_of_image : 0;
}

inline uint32_t get_entry_point_rva(void* image) {
    const auto nt = get_nt_headers(image);
    return nt ? nt->optional_header.address_of_entry_point : 0;
}

inline void* rva_to_va(void* image_base, uint32_t rva) {
    return reinterpret_cast<void*>(
        reinterpret_cast<uint64_t>(image_base) + rva
    );
}

} // namespace loader
