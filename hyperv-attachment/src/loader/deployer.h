#pragma once
// =============================================================================
// VMM Shadow Mapper - Payload Deployer
// Coordinates loading of DKOM and RWbase payloads into Guest kernel space
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

// Deploy DKOM payload (one-shot execution, self-destructing)
// - Validates embedded payload
// - Allocates executable memory in Guest
// - Applies relocations, resolves imports, fixes cookie
// - Executes EntryPoint
// - Zeroes memory after execution
// @param ntoskrnl_base: Guest ntoskrnl.exe base address
// @return: Deployment result code
deploy_result_t deploy_dkom_payload(uint64_t ntoskrnl_base);

// Deploy RWbase payload (persistent service, SLAT hidden)
// - Same as DKOM but with SLAT No-Access hiding after setup
// @param ntoskrnl_base: Guest ntoskrnl.exe base address
// @return: Deployment result code
deploy_result_t deploy_rwbase_payload(uint64_t ntoskrnl_base);

// Check if payloads are ready for deployment
bool is_payload_ready();

} // namespace loader
