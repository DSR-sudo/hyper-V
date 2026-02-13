#include "payload_validation.h"

/**
 * @description 校验载荷内容是否可用。
 * @param {const std::uint8_t*} payload 载荷首地址。
 * @param {const std::uint32_t} payload_size 载荷长度（字节）。
 * @return {bool} 是否为有效载荷。
 * @throws {无} 不抛出异常。
 * @example
 * const bool ok = validate_payload(payload, payload_size);
 */
bool validate_payload(const std::uint8_t* payload, const std::uint32_t payload_size)
{
    // 业务说明：基础输入校验，避免空指针与空载荷进入后续流程。
    // 输入：payload 与 payload_size；输出：校验结果；规则：指针为空或长度为零则失败；异常：不抛出。
    if (!payload || payload_size == 0)
    {
        return false;
    }

    // 业务说明：扫描载荷内容，避免出现非法空字节。
    // 输入：payload 内容；输出：校验结果；规则：发现空字节即失败；异常：不抛出。
    for (std::uint32_t i = 0; i < payload_size; ++i)
    {
        if (payload[i] == 0)
        {
            return false;
        }
    }

    return true;
}
