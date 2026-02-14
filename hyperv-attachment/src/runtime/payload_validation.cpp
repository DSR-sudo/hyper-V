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
    // 业务说明：验证 Payload 的基础合法性。
    // 输入：payload/payload_size；输出：校验结果；规则：目前仅做基础指针与大小校验；异常：不抛出。
    if (!payload || payload_size < 0x40) // Minimum PE header size
    {
        return false;
    }

    // 检查 MZ 签名
    if (payload[0] != 'M' || payload[1] != 'Z')
    {
        return false;
    }

    return true;
}
