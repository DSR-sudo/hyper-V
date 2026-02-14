#include "violation.h"
#include "../cr3/cr3.h"
#include "../hook/hook_entry.h"
#include "../../arch/arch.h"

/**
 * @description 处理 SLAT Violation（EPT 异常）。
 * @param {slat::context_t*} ctx SLAT 上下文。
 * @return {std::uint8_t} 是否已处理。
 * @throws {无} 不抛出异常。
 * @example
 * slat::violation::process(ctx);
 */
std::uint8_t slat::violation::process(context_t* ctx)
{
    // Intel Logic Only
    const auto qualification = arch::get_exit_qualification();

    if (!qualification.caused_by_translation)
    {
        return 0;
    }

    const std::uint64_t physical_address = arch::get_guest_physical_address();
    const hook::entry_t* const hook_entry = hook::entry_t::find(ctx, physical_address >> 12);

    // [Logic A] TLB Self-Healing: If stale violation detected (hook no longer exists)
    if (hook_entry == nullptr)
    {
        // Immediately flush local core TLB and switch back to Stealth view to break infinite loop
        if (get_cr3().flags != hyperv_cr3(ctx).flags)
        {
            set_cr3(hyperv_cr3(ctx));
        }
        else
        {
            // If already in hyperv_cr3 but still triggering Violation, TLB is definitely stale
            flush_current_logical_processor_cache();
        }
        return 0;
    }

    if (qualification.execute_access)
    {
        const cr3 hv_cr3 = hyperv_cr3(ctx);
        if (get_cr3().flags != hv_cr3.flags)
        {
            set_cr3(hv_cr3);
        }
    }
    else
    {
        const cr3 target_hook_cr3 = hook_cr3(ctx);
        if (get_cr3().flags != target_hook_cr3.flags)
        {
            set_cr3(target_hook_cr3);
        }

        // [Logic B] Single-Page Exposure: Enable MTF to trace back immediately after instruction execution
        arch::enable_mtf();
    }

    return 1;
}

/**
 * @description 处理 MTF（监控陷阱标志）回调。
 * @param {slat::context_t*} ctx SLAT 上下文。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * slat::violation::handle_mtf(ctx);
 */
void slat::violation::handle_mtf(context_t* ctx)
{
    // [Logic C] MTF Callback: Switch back to Stealth view and disable MTF once instruction succeeds
    const cr3 hv_cr3 = hyperv_cr3(ctx);
    if (get_cr3().flags != hv_cr3.flags)
    {
        set_cr3(hv_cr3);
    }

    arch::disable_mtf();
}
