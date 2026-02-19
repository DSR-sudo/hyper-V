#pragma once
// =============================================================================
// VMM Shadow Mapper - Unified Loader Header
// Include this single header to access all loader functionality
// =============================================================================

#include <cstddef>
#include <cstdint>
#include "pe.h"
#include "reloc.h"
#include "imports.h"
#include "cookie.h"
#include "guest.h"

namespace loader {

struct section_info_t {
    uint32_t virtual_address;
    uint32_t virtual_size;
    uint32_t raw_size;
    uint32_t characteristics;
};

struct allocation_info_t {
    void*    host_buffer;
    uint32_t size;
    uint32_t page_count;
};

bool validate_payload(const unsigned char* data, size_t size);
bool is_payload_ready();
bool get_payload_section_info(const unsigned char* image, size_t image_size, uint16_t section_index, section_info_t* out_info);
bool allocate_payload_staging_buffer(context_t* ctx, uint32_t size, allocation_info_t* out_info);
void free_payload_staging_buffer(context_t* ctx, const allocation_info_t* alloc);
bool map_sections(void* dest, const unsigned char* src, size_t src_size);
bool apply_section_permissions(context_t* ctx, uint64_t target_va, const unsigned char* image, size_t image_size);
bool wipe_pe_headers(context_t* ctx, uint64_t target_va, const unsigned char* image, size_t image_size);

} // namespace loader
