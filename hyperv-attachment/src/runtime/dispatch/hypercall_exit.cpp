#include "hypercall_exit.h"
#include "../../hypercall/hypercall.h"
#include <hypercall/hypercall_def.h>
#include "../../modules/arch/arch.h"
#include "../../shared/structures/trap_frame.h"

namespace
{
    /**
     * @description 判断是否为合法的 Hypercall 请求。
     * @param {const hypercall_info_t&} hypercall_info Hypercall 关键信息，包含主次校验键。
     * @return {bool} 是否匹配 Hypercall 主次校验键。
     * @throws {无} 不抛出异常。
     */
    bool is_hypercall_request(const hypercall_info_t& hypercall_info)
    {
        return hypercall_info.primary_key == hypercall_primary_key && hypercall_info.secondary_key == hypercall_secondary_key;
    }
}

bool try_process_hypercall_exit(const std::uint64_t a1)
{
    // 业务说明：从 TrapFrame 提取 Hypercall 信息并校验密钥。
    // 输入：VMExit TrapFrame 指针；输出：是否处理；规则：密钥匹配才处理；异常：不抛出。
    trap_frame_t* const trap_frame = *reinterpret_cast<trap_frame_t**>(a1);
    const hypercall_info_t hypercall_info = { .value = trap_frame->rcx };

    if (!is_hypercall_request(hypercall_info))
    {
        return false;
    }

    // 业务说明：保存与恢复来宾栈指针，执行 Hypercall 处理并推进来宾 RIP。
    // 输入：trap_frame 与 hypercall_info；输出：处理结果；规则：执行后推进 RIP；异常：不抛出。
    trap_frame->rsp = arch::get_guest_rsp();
    hypercall::process(hypercall_info, trap_frame);
    arch::set_guest_rsp(trap_frame->rsp);
    arch::advance_guest_rip();
    return true;
}
