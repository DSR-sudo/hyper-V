#include "runtime_context.h"

// 业务说明：全局运行时上下文实例定义。
// 背景：为了遵守“工具函数不允许设置私有变量”的规则，所有全局状态被移动到业务层的此实例中。
runtime_context_t g_runtime_context = { };
extern "C" std::uint64_t original_nmi_handler = 0;
extern "C" interrupts::context_t* g_interrupts_ctx_ptr = nullptr;
