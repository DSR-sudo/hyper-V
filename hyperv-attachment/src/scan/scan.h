#pragma once
#include <cstdint>
#include <ia32-doc/ia32.hpp>

namespace scan {

/**
 * @brief 在 Guest 虚拟内存中搜索特定的特征码
 * 
 * @param slat_cr3 SLAT (Extended Page Tables) 的 CR3
 * @param guest_cr3 Guest 操作系统的 CR3 (用于地址翻译)
 * @param base_address 搜索的起始虚拟地址 (通常是内核基址)
 * @param size 搜索的范围大小
 * @param signature 特征码字符串，例如 "48 89 5C 24 ? 48 89 6C 24"
 * @return std::uint64_t 找到的虚拟地址，若未找到则返回 0
 */
std::uint64_t find_pattern(cr3 slat_cr3, cr3 guest_cr3, std::uint64_t base_address, std::uint32_t size, const char* signature);

/**
 * @brief 搜索特定的函数
 * 
 * @param slat_cr3 SLAT CR3
 * @param guest_cr3 Guest CR3
 * @param kernel_base 内核基址
 * @param signature 特征码
 * @return std::uint64_t 函数地址
 */
std::uint64_t find_function(cr3 slat_cr3, cr3 guest_cr3, std::uint64_t kernel_base, const char* signature);

} // namespace scan
