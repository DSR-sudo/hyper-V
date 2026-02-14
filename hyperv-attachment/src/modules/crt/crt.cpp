#include "crt.h"
#include <intrin.h>

extern "C"
{
    __int64 _InterlockedCompareExchange64(__int64 volatile * Destination, __int64 Exchange, __int64 Comperand);
    __int64 _InterlockedExchange64(__int64 volatile * Target, __int64 Value);
}

#pragma intrinsic(_InterlockedCompareExchange64)
#pragma intrinsic(_InterlockedExchange64)

/**
 * @description 拷贝内存区域。
 * @param {void* const} destination 目标地址。
 * @param {const void* const} source 源地址。
 * @param {const std::uint64_t} size 拷贝字节数。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * crt::copy_memory(dst, src, size);
 */
void crt::copy_memory(void* const destination, const void* const source, const std::uint64_t size)
{
	// 业务说明：使用内建指令执行内存拷贝，确保无 CRT 依赖。
	// 输入：destination/source/size；输出：destination 内容更新；规则：按字节拷贝；异常：不抛出。
	__movsb(static_cast<std::uint8_t*>(destination), static_cast<const std::uint8_t*>(source), size);
}

/**
 * @description 设置内存区域为指定字节值。
 * @param {void* const} destination 目标地址。
 * @param {const std::uint8_t} value 填充值。
 * @param {const std::uint64_t} size 填充字节数。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * crt::set_memory(buffer, 0, length);
 */
void crt::set_memory(void* const destination, const std::uint8_t value, const std::uint64_t size)
{
	// 业务说明：使用内建指令填充内存区域，确保无 CRT 依赖。
	// 输入：destination/value/size；输出：destination 内容被填充；规则：按字节填充；异常：不抛出。
	__stosb(static_cast<std::uint8_t*>(destination), value, size);
}

/**
 * @description 计算字符串长度。
 * @param {const char*} string 输入字符串。
 * @return {std::uint64_t} 字符串长度。
 * @throws {无} 不抛出异常。
 * @example
 * const auto len = crt::string_length("test");
 */
std::uint64_t crt::string_length(const char* string)
{
	// 业务说明：遍历字符串直到遇到 null 终止符。
	// 输入：string；输出：字符串长度；规则：按字符计数；异常：不抛出。
	if (!string) return 0;
	std::uint64_t length = 0;
	while (string[length]) length++;
	return length;
}

// Forward declarations with C linkage
extern "C" void* __cdecl memset(void*, int, unsigned __int64);
extern "C" void* __cdecl memcpy(void*, const void*, unsigned __int64);

#pragma function(memset, memcpy)

/**
 * @description 提供无 CRT 依赖的 memset 实现。
 * @param {void*} dest 目标地址。
 * @param {int} val 填充值。
 * @param {unsigned __int64} count 填充字节数。
 * @return {void*} 返回目标地址。
 * @throws {无} 不抛出异常。
 * @example
 * memset(buffer, 0, size);
 */
extern "C" void* __cdecl memset(void* dest, int val, unsigned __int64 count)
{
	// 业务说明：将 memset 路由到自定义内存填充实现。
	// 输入：dest/val/count；输出：dest 内容被填充；规则：按字节填充；异常：不抛出。
	crt::set_memory(dest, static_cast<std::uint8_t>(val), count);
	return dest;
}

/**
 * @description 提供无 CRT 依赖的 memcpy 实现。
 * @param {void*} dest 目标地址。
 * @param {const void*} src 源地址。
 * @param {unsigned __int64} count 拷贝字节数。
 * @return {void*} 返回目标地址。
 * @throws {无} 不抛出异常。
 * @example
 * memcpy(dst, src, size);
 */
extern "C" void* __cdecl memcpy(void* dest, const void* src, unsigned __int64 count)
{
	// 业务说明：将 memcpy 路由到自定义内存拷贝实现。
	// 输入：dest/src/count；输出：dest 内容被更新；规则：按字节拷贝；异常：不抛出。
	crt::copy_memory(dest, src, count);
	return dest;
}

/**
 * @description 获取互斥锁，阻塞直到成功。
 * @param {void} 无。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * mutex.lock();
 */
void crt::mutex_t::lock()
{
	// 业务说明：使用原子交换自旋等待锁释放。
	// 输入：无；输出：锁被获取；规则：自旋直到成功；异常：不抛出。
	while (_InterlockedCompareExchange64(&value_, 1, 0) != 0)
	{
		_mm_pause();
	}
}

/**
 * @description 尝试获取互斥锁。
 * @param {void} 无。
 * @return {bool} 是否获取成功。
 * @throws {无} 不抛出异常。
 * @example
 * const bool ok = mutex.try_lock();
 */
bool crt::mutex_t::try_lock()
{
	// 业务说明：单次原子交换检测锁状态。
	// 输入：无；输出：是否获取成功；规则：不阻塞；异常：不抛出。
	if (_InterlockedCompareExchange64(&value_, 1, 0) == 0)
	{
		return true;
	}

	return false;
}

/**
 * @description 释放互斥锁。
 * @param {void} 无。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * mutex.release();
 */
void crt::mutex_t::release()
{
	// 业务说明：将锁状态复位为可用。
	// 输入：无；输出：锁释放；规则：原子交换；异常：不抛出。
	_InterlockedExchange64(&value_, 0);
}

/**
 * @description 将位图全部置位。
 * @param {void} 无。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * bitmap.set_all();
 */
void crt::bitmap_t::set_all() const
{
    // 业务说明：按行写满位图，快速初始化全 1 状态。
    // 输入：value_/count_；输出：位图内容更新；规则：value_ 为空则忽略；异常：不抛出。
    if (value_ == nullptr)
    {
        return;
    }

    for (size_type i = 0; i < count_; i++)
    {
        value_type& row_state = value_[i];

        row_state = value_max;
    }
}

/**
 * @description 设置指定索引位。
 * @param {const value_type} index 目标位索引。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * bitmap.set(3);
 */
void crt::bitmap_t::set(const value_type index) const
{
    // 业务说明：定位目标位所在行并置位。
    // 输入：index；输出：位图更新；规则：行为空则忽略；异常：不抛出。
    if (value_ == nullptr)
    {
        return;
    }

    const size_type row_id = static_cast<size_type>(index / bit_count_in_row);
    if (count_ <= row_id)
    {
        return;
    }

    const std::uint64_t bit = index % bit_count_in_row;
    value_[row_id] |= 1ull << bit;
}

/**
 * @description 清除指定索引位。
 * @param {const value_type} index 目标位索引。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * bitmap.clear(3);
 */
void crt::bitmap_t::clear(const value_type index) const
{
    // 业务说明：定位目标位所在行并清零。
    // 输入：index；输出：位图更新；规则：行为空则忽略；异常：不抛出。
    if (value_ == nullptr)
    {
        return;
    }

    const size_type row_id = static_cast<size_type>(index / bit_count_in_row);
    if (count_ <= row_id)
    {
        return;
    }

    const size_type bit = index % bit_count_in_row;
    value_[row_id] &= ~(1ull << bit);
}

/**
 * @description 判断指定索引位是否为 1。
 * @param {const value_type} index 目标位索引。
 * @return {bit_type} 位状态。
 * @throws {无} 不抛出异常。
 * @example
 * const auto set = bitmap.is_set(3);
 */
crt::bitmap_t::bit_type crt::bitmap_t::is_set(const value_type index) const
{
    // 业务说明：读取指定索引位的状态。
    // 输入：index；输出：位状态；规则：行为空返回 0；异常：不抛出。
    if (value_ == nullptr)
    {
        return 0;
    }

    const size_type row_id = static_cast<size_type>(index / bit_count_in_row);
    if (count_ <= row_id)
    {
        return 0;
    }

    const value_type row_value = value_[row_id];
    const size_type bit = index % bit_count_in_row;

    return (row_value >> bit) & 1;
}

/**
 * @description 绑定位图存储指针。
 * @param {const pointer} value 位图数据指针。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * bitmap.set_value(buffer);
 */
void crt::bitmap_t::set_value(const pointer value)
{
    // 业务说明：设置位图底层存储指针。
    // 输入：value；输出：value_ 更新；规则：直接赋值；异常：不抛出。
    value_ = value;
}

/**
 * @description 设置位图行数。
 * @param {const size_type} value_count 行数。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * bitmap.set_count(count);
 */
void crt::bitmap_t::set_count(const size_type value_count)
{
    // 业务说明：记录位图的行数用于边界判断。
    // 输入：value_count；输出：count_ 更新；规则：直接赋值；异常：不抛出。
    count_ = value_count;
}

/**
 * @description 获取指定索引所在的位图行指针。
 * @param {const value_type} index 位索引。
 * @return {pointer} 行指针，失败返回 nullptr。
 * @throws {无} 不抛出异常。
 * @example
 * auto row_ptr = bitmap.row(index);
 */
crt::bitmap_t::pointer crt::bitmap_t::row(const value_type index) const
{
    // 业务说明：根据索引计算行号并进行范围检查。
    // 输入：index；输出：行指针；规则：越界返回 nullptr；异常：不抛出。
    if (value_ == nullptr)
    {
        return nullptr;
    }

    const size_type row_id = static_cast<size_type>(index / bit_count_in_row);

    if (count_ <= row_id)
    {
        return nullptr;
    }

    return &value_[row_id];
}
