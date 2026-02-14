#include "runtime_context.h"

// 业务说明：全局运行时上下文实例定义。
// 背景：为了遵守“工具函数不允许设置私有变量”的规则，所有全局状态被移动到业务层的此实例中。
// 这里的 g_runtime_context 不使用 = { } 显式初始化，而是利用全局变量默认零初始化的特性。
// 这样编译器会将其放入 .bss 段（未初始化数据段），只在运行时占用内存，不占用磁盘文件体积。
runtime_context_t g_runtime_context;
extern "C" std::uint64_t original_nmi_handler = 0;
extern "C" interrupts::context_t* g_interrupts_ctx_ptr = nullptr;
