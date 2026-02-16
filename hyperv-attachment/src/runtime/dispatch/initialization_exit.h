#pragma once

/**
 * @description 处理首次 VMExit 以及分阶段部署逻辑。
 * @throws {无} 不抛出异常。
 */
void process_first_vmexit();

/**
 * @description 清理 UEFI 启动镜像，抹除其物理内存内容。
 * @throws {无} 不抛出异常。
 */
void clean_up_uefi_boot_image();
