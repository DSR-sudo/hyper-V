#pragma once
#include <cstdint>
#include "../arch/arch.h"

namespace loader {
namespace scan {

    // 搜索指定大小的Codecave（前后均为0xCC填充）
    // size: 需要的空间大小
    // 返回: Guest物理地址，如果未找到则返回0
    uint64_t find_codecave(uint32_t size, std::uint64_t ntoskrnl_base);

    // 清除Codecave内容（恢复为0xCC）
    // address: Guest物理地址
    // size: 要清除的大小
    void clear_codecave(uint64_t address, uint32_t size);

} // namespace scan
} // namespace loader
