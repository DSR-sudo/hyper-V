#pragma once
#include <cstdint>

/**
 * @description 设置 VMExit 运行时状态与 UEFI 镜像信息。
 * @param {std::uint8_t*} original_vmexit_handler_routine 原始 VMExit 处理器地址。
 * @param {std::uint64_t} uefi_boot_physical_base_address UEFI Boot 镜像物理基址。
 * @param {std::uint64_t} uefi_boot_image_size UEFI Boot 镜像大小。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * set_vmexit_runtime_state(original_handler, uefi_base, uefi_size);
 */
void set_vmexit_runtime_state(std::uint8_t* original_vmexit_handler_routine, std::uint64_t uefi_boot_physical_base_address, std::uint64_t uefi_boot_image_size);

/**
 * @description 设置 ntoskrnl 基址供 VMExit/导出解析使用。
 * @param {std::uint64_t} ntoskrnl_base ntoskrnl.exe 基址。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * set_ntoskrnl_base(ntoskrnl_base_from_uefi);
 */
void set_ntoskrnl_base(std::uint64_t ntoskrnl_base);

/**
 * @description 获取当前 ntoskrnl 基址。
 * @param {void} 无。
 * @return {std::uint64_t} 当前保存的 ntoskrnl 基址。
 * @throws {无} 不抛出异常。
 * @example
 * const auto base = get_ntoskrnl_base();
 */
std::uint64_t get_ntoskrnl_base();

/**
 * @description VMExit 入口函数，完成首次处理与分发逻辑。
 * @param {const std::uint64_t} a1 VMExit 参数1。
 * @param {const std::uint64_t} a2 VMExit 参数2。
 * @param {const std::uint64_t} a3 VMExit 参数3。
 * @param {const std::uint64_t} a4 VMExit 参数4。
 * @return {std::uint64_t} VMExit 返回值。
 * @throws {无} 不抛出异常。
 * @example
 * const auto result = vmexit_handler_detour(a1, a2, a3, a4);
 */
std::uint64_t vmexit_handler_detour(std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4);
