#include "scan.h"
#include "../memory_manager/memory_manager.h"
#include "../crt/crt.h"
#include "../logs/logs.h"

namespace scan {

static std::uint8_t hex_to_byte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

static std::uint8_t g_pattern_bytes[256];
static bool g_pattern_mask[256];
static std::uint8_t g_scan_buffer[0x1100];

static void parse_signature(const char* signature, std::uint8_t* bytes, bool* mask, std::uint32_t& length) {
    length = 0;
    const char* current = signature;
    while (*current && length < 256) {
        if (*current == ' ') {
            current++;
            continue;
        }
        if (*current == '?') {
            mask[length] = false;
            bytes[length] = 0;
            current++;
            if (*current == '?') current++; // Handle ??
        } else if (*(current + 1)) {
            mask[length] = true;
            bytes[length] = (hex_to_byte(current[0]) << 4) | hex_to_byte(current[1]);
            current += 2;
        } else {
            // Unexpected end of string
            break;
        }
        length++;
    }
}

std::uint64_t find_pattern(cr3 slat_cr3, cr3 guest_cr3, std::uint64_t base_address, std::uint32_t size, const char* signature) {
    std::uint32_t pattern_length = 0;

    parse_signature(signature, g_pattern_bytes, g_pattern_mask, pattern_length);

    if (pattern_length == 0) {
        logs::print("[Scan] Error: Invalid signature or pattern length is 0.\n");
        return 0;
    }

    const std::uint32_t block_size = 0x1000;

    for (std::uint32_t offset = 0; offset < size; offset += block_size) {
        std::uint32_t remaining_size = size - offset;
        std::uint32_t read_size = crt::min(block_size + pattern_length - 1, remaining_size);
        
        std::uint64_t bytes_read = memory_manager::operate_on_guest_virtual_memory(
            slat_cr3, g_scan_buffer, base_address + offset, guest_cr3, read_size, memory_operation_t::read_operation);

        if (bytes_read < pattern_length) {
            if (bytes_read == 0 && offset < size) {
                continue;
            }
            break; 
        }

        for (std::uint32_t i = 0; i <= bytes_read - pattern_length; i++) {
            bool found = true;
            for (std::uint32_t j = 0; j < pattern_length; j++) {
                if (g_pattern_mask[j] && g_scan_buffer[i + j] != g_pattern_bytes[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return base_address + offset + i;
            }
        }
        
        if (bytes_read < read_size) {
            break;
        }
    }

    return 0;
}

std::uint64_t find_function(cr3 slat_cr3, cr3 guest_cr3, std::uint64_t kernel_base, const char* signature) {
    // Default scan range: 32MB for ntoskrnl.exe
    return find_pattern(slat_cr3, guest_cr3, kernel_base, 0x2000000, signature);
}

} // namespace scan
