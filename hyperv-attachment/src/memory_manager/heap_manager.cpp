#include "heap_manager.h"
#include "../crt/crt.h"
#include <intrin.h>

#include "memory_manager.h"

namespace
{
	constexpr std::uint64_t heap_block_size = 0x1000;

	heap_manager::heap_entry_t* free_block_list_head = nullptr;

	crt::mutex_t allocation_mutex = { };
}

/**
 * @description 初始化堆管理器空闲块链表。
 * @param {void* const} heap_base 堆起始地址。
 * @param {const std::uint64_t} heap_size 堆大小。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * heap_manager::set_up(base, size);
 */
void heap_manager::set_up(void* const heap_base, const std::uint64_t heap_size)
{
	// 业务说明：按固定块大小构建空闲链表。
	// 输入：heap_base/heap_size；输出：free_block_list_head；规则：逐块链接；异常：不抛出。
	free_block_list_head = static_cast<heap_entry_t*>(heap_base);

	const std::uint64_t heap_entries = heap_size / heap_block_size;

	heap_entry_t* entry = free_block_list_head;

	for (std::uint64_t i = 1; i < heap_entries - 1; i++)
	{
		entry->set_next(reinterpret_cast<heap_entry_t*>(reinterpret_cast<std::uint8_t*>(entry) + heap_block_size));

		entry = entry->next();
	}

	entry->set_next(nullptr);
}

/**
 * @description 分配一页堆内存。
 * @param {void} 无。
 * @return {void*} 分配到的页地址，失败返回 nullptr。
 * @throws {无} 不抛出异常。
 * @example
 * auto* page = heap_manager::allocate_page();
 */
void* heap_manager::allocate_page()
{
	// 业务说明：加锁从空闲链表取出一个块。
	// 输入：无；输出：页地址；规则：空闲链表为空返回 nullptr；异常：不抛出。
	allocation_mutex.lock();

	heap_entry_t* const entry = free_block_list_head;

	if (entry == nullptr)
	{
		allocation_mutex.release();

		return nullptr;
	}

	free_block_list_head = entry->next();

	allocation_mutex.release();

	return entry;
}

/**
 * @description 分配一页并返回物理地址。
 * @param {void} 无。
 * @return {std::uint64_t} 物理地址，失败返回 0。
 * @throws {无} 不抛出异常。
 * @example
 * auto phys = heap_manager::allocate_physical_page();
 */
std::uint64_t heap_manager::allocate_physical_page()
{
	// 业务说明：分配页并转换为物理地址。
	// 输入：无；输出：物理地址；规则：分配失败返回 0；异常：不抛出。
	const void* const allocation_ptr = allocate_page();

	if (allocation_ptr == nullptr)
	{
		return 0;
	}

	return memory_manager::unmap_host_physical(allocation_ptr);
}

/**
 * @description 释放一页堆内存。
 * @param {void* const} allocation_base 需要释放的页地址。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * heap_manager::free_page(page);
 */
void heap_manager::free_page(void* const allocation_base)
{
	// 业务说明：将释放页插回空闲链表。
	// 输入：allocation_base；输出：空闲链表更新；规则：空指针直接返回；异常：不抛出。
	if (allocation_base == nullptr)
	{
		return;
	}

	allocation_mutex.lock();

	const auto entry = static_cast<heap_entry_t*>(allocation_base);

	entry->set_next(free_block_list_head);
	free_block_list_head = entry;

	allocation_mutex.release();
}

/**
 * @description 获取当前空闲页数量。
 * @param {void} 无。
 * @return {std::uint64_t} 空闲页数量。
 * @throws {无} 不抛出异常。
 * @example
 * const auto count = heap_manager::get_free_page_count();
 */
std::uint64_t heap_manager::get_free_page_count()
{
	// 业务说明：遍历空闲链表统计页数量。
	// 输入：无；输出：空闲页数量；规则：逐节点计数；异常：不抛出。
	allocation_mutex.lock();

	std::uint64_t count = 0;

	const heap_entry_t* entry = free_block_list_head;

	while (entry != nullptr)
	{
		count++;

		entry = entry->next();
	}

	allocation_mutex.release();

	return count;
}

/**
 * @description 获取堆条目的下一个节点。
 * @param {void} 无。
 * @return {heap_entry_t*} 下一个条目指针。
 * @throws {无} 不抛出异常。
 * @example
 * auto* next = entry->next();
 */
heap_manager::heap_entry_t* heap_manager::heap_entry_t::next() const
{
	// 业务说明：返回链表中的下一个条目指针。
	// 输入：无；输出：next_；规则：直接返回；异常：不抛出。
	return next_;
}

/**
 * @description 设置堆条目的下一个节点。
 * @param {heap_entry_t* const} next 下一个条目指针。
 * @return {void} 无返回值。
 * @throws {无} 不抛出异常。
 * @example
 * entry->set_next(next);
 */
void heap_manager::heap_entry_t::set_next(heap_entry_t* const next)
{
	// 业务说明：更新链表指针。
	// 输入：next；输出：next_ 更新；规则：直接赋值；异常：不抛出。
	next_ = next;
}
