#include "violation.h"
#include "../cr3/cr3.h"
#include "../hook/hook_entry.h"
#include "../../arch/arch.h"

std::uint8_t slat::violation::process()
{
    // Intel Logic Only
    const auto qualification = arch::get_exit_qualification();

    if (!qualification.caused_by_translation)
    {
        return 0;
    }

    const std::uint64_t physical_address = arch::get_guest_physical_address();
    const hook::entry_t* const hook_entry = hook::entry_t::find(physical_address >> 12);

    if (hook_entry == nullptr)
    {
        if (qualification.execute_access)
        {
            set_cr3(hyperv_cr3());
        }
        return 0;
    }

    if (qualification.execute_access)
    {
        set_cr3(hyperv_cr3());
    }
    else
    {
        set_cr3(hook_cr3());
    }

    return 1;
}
