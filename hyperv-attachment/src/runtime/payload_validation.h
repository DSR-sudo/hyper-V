#pragma once
#include <cstdint>

/**
 * @description 校验载荷内容是否可用。
 * @param {const std::uint8_t*} payload 载荷首地址。
 * @param {const std::uint32_t} payload_size 载荷长度（字节）。
 * @return {bool} 是否为有效载荷。
 * @throws {无} 不抛出异常。
 * @example
 * const bool ok = validate_payload(payload, payload_size);
 */
bool validate_payload(const std::uint8_t* payload, std::uint32_t payload_size);
