#pragma once
// =============================================================================
// VMM Shadow Mapper - Payload Deployer (Business Management Module)
// Coordinates loading of RWbase payloads into Guest kernel space.
// This module orchestrates various loader tools to achieve payload deployment.
// =============================================================================

#include <cstdint>
#include "modules/loader/guest.h"

namespace loader {

// Deployment result codes
enum class deploy_result_t : uint32_t {
    success = 0,
    already_in_progress,
    invalid_payload,
    relocation_failed,
    import_resolution_failed,
    cookie_fix_failed,
    memory_allocation_failed,
    entrypoint_execution_failed,
};

// =============================================================================
// Dynamic Injection Helpers (Stage Machine Support)
// =============================================================================

// Stage 1: Hijack current thread to call MmAllocateIndependentPagesEx
bool prepare_allocation_hijack(context_t* ctx, void* trap_frame);

// Stage 2: Harvest allocation result (RAX) and restore original context
bool harvest_allocation_result(context_t* ctx, void* trap_frame);

// Stage 3: Write payload to allocated memory and hijack execution
bool execute_payload_hijack(context_t* ctx, void* trap_frame);

} // namespace loader
