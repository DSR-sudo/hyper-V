#pragma once
#include <cstdint>
#include "../../shared/structures/trap_frame.h"

/**
 * @description 全局注入状态机维护逻辑
 * @param guest_rip Guest RIP
 * @param trap_frame Trap Frame
 * @return bool 如果处理了 Magic Trap 并需要立即返回，则返回 true
 */
bool process_injection_state_tick(uint64_t guest_rip, trap_frame_t* trap_frame);

/**
 * @description 处理 #DB 异常注入点
 * @param {trap_frame_t*} trap_frame Trap Frame 指针。
 * @return {bool} 是否成功处理注入逻辑。
 */
bool handle_injection_db_exit(trap_frame_t* trap_frame);
