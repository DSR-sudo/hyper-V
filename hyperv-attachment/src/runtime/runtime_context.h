﻿#pragma once
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

// 业务说明：注入流程状态机，控制跨核流程与执行流劫持的全局状态。
// 输入：外部通过状态流转驱动；输出：注入流程状态与关键现场数据；规则：仅存储状态不执行逻辑。
struct injection_ctx_t
{
    // State Machine
    std::atomic<uint64_t> injection_counter; // Warm-up counter (Stage 0)
    std::atomic<uint32_t> stage;             // 0=Warmup, 1=Configuration (DR7), 2=Interception (Done)

    // Injection Target
    std::atomic<uint64_t> target_address;

    // Context Data
    trap_frame_t  saved_guest_context;       // Full backup for Allocator Hijack
    std::uint64_t saved_rip;                 // Backup for Guest RIP (not in trap_frame_t)
    std::uint64_t allocated_buffer;          // Result from MmAllocate
    std::uint64_t allocation_routine;        // Address of MmAllocateIndependentPagesEx
    
    // Magic Trap Configuration
    static constexpr uint64_t MAGIC_TRAP_RIP = 0xFFFFF88877776666ULL; // Virtual address to catch return
};

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

    injection_ctx_t injection_ctx;

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
