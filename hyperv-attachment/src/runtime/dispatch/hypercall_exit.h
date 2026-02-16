#pragma once
#include <cstdint>

/**
 * @description 尝试处理 Hypercall VMExit 请求。
 * @param {const std::uint64_t} a1 VMExit 上下文参数。
 * @return {bool} 是否为 Hypercall 并已处理。
 * @throws {无} 不抛出异常。
 */
bool try_process_hypercall_exit(const std::uint64_t a1);
