#pragma once
#include <cstdint>
#include <structures/trap_frame.h>
#include <modules/crt/crt.h>
#include <atomic>

#include <modules/slat/slat.h>
#include <modules/logs/logs.h>
#include <modules/memory_manager/heap_manager.h>
#include <modules/interrupts/interrupts.h>
#include <modules/loader/guest.h>
#include <modules/apic/apic.h>

// 业务说明：全局运行时上下文，集中管理所有模块的状态，确保工具模块保持无状态。
// 输入：各模块初始化参数；输出：全局统一的状态访问接口；规则：工具模块不得持有此类状态。
struct runtime_context_t
{
    // Logs state
    logs::context_t log_ctx;

    // SLAT state
    slat::context_t slat_ctx;

    // Memory state
    heap_manager::context_t heap_ctx;

    // Interrupts/APIC state
    interrupts::context_t interrupts_ctx;
    crt::bitmap_t nmi_ready_bitmap;
    std::uint64_t* nmi_ready_bitmap_storage;
    apic_t* apic_instance;
    void* apic_allocation_ptr;
    std::uint64_t original_nmi_handler;

    // Loader state
    loader::context_t loader_ctx;

    // VMExit state
    std::uint8_t* original_vmexit_handler;
    std::uint64_t uefi_boot_physical_base_address;
    std::uint64_t uefi_boot_image_size;
    std::uint64_t ntoskrnl_base;
    std::uint8_t is_first_vmexit;
    std::uint8_t has_hidden_heap_pages;
    std::uint64_t vmexit_count;

    // Image boundaries (Self-protection/Stealth)
    std::uint64_t image_base;
    std::uint64_t image_size;
    std::uint64_t text_start;
    std::uint64_t text_end;
    std::uint64_t data_start;
    std::uint64_t data_end;
};

extern runtime_context_t g_runtime_context;
extern "C" std::uint64_t original_nmi_handler;
extern "C" interrupts::context_t* g_interrupts_ctx_ptr;
