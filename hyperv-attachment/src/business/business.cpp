#include "business.h"
#include "driver_instrumentation/driver_instrumentation.h"

namespace business {
namespace {
const core::business_callbacks g_callbacks = {
    &driver_instrumentation::on_first_vmexit,
    &driver_instrumentation::on_vmexit};
}

const core::business_callbacks *callbacks() { return &g_callbacks; }
} // namespace business
