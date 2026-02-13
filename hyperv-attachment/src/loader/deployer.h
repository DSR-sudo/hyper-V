#pragma once
// =============================================================================
// VMM Shadow Mapper - Payload Deployer
// Coordinates loading of RWbase payloads into Guest kernel space
// =============================================================================

#include <cstdint>

namespace loader {

// Deployment result codes
enum class deploy_result_t : uint32_t {
    success = 0,
    invalid_payload,
    relocation_failed,
    import_resolution_failed,
    cookie_fix_failed,
    memory_allocation_failed,
    entrypoint_execution_failed,
};

// Deploy RWbase payload (persistent service, SLAT hidden)
// - Validates embedded payload
// - Allocates executable memory in Guest
// - Applies relocations, resolves imports, fixes cookie
// - Executes EntryPoint
// - Same as original payload but with SLAT No-Access hiding after setup
// @param ntoskrnl_base: Guest ntoskrnl.exe base address
// @return: Deployment result code
deploy_result_t deploy_rwbase_payload(uint64_t ntoskrnl_base);

// Check if payloads are ready for deployment
bool is_payload_ready();

} // namespace loader
