#include "memory_manager.h"

#include "../crt/crt.h"
#include "../slat/slat.h"

constexpr std::uint64_t host_physical_memory_access_base = 255ull << 39;

/**
 * @description 映射宿主物理地址到线性地址。
 * @param {const std::uint64_t} host_physical_address 宿主物理地址。
 * @return {void*} 线性映射地址。
 * @throws {无} 不抛出异常。
 * @example
 * auto* va = memory_manager::map_host_physical(phys);
 */
void* memory_manager::map_host_physical(const std::uint64_t host_physical_address)
{
	// 业务说明：使用固定基址对宿主物理地址进行直映。
	// 输入：host_physical_address；输出：映射后的线性地址；规则：基址偏移；异常：不抛出。
	return reinterpret_cast<void*>(host_physical_memory_access_base + host_physical_address);
}

/**
 * @description 反向转换宿主线性映射地址为物理地址。
 * @param {const void* const} host_mapped_address 线性映射地址。
 * @return {std::uint64_t} 宿主物理地址。
 * @throws {无} 不抛出异常。
 * @example
 * auto phys = memory_manager::unmap_host_physical(mapped);
 */
std::uint64_t memory_manager::unmap_host_physical(const void* const host_mapped_address)
{
	// 业务说明：从固定基址反算宿主物理地址。
	// 输入：host_mapped_address；输出：物理地址；规则：基址反推；异常：不抛出。
	return reinterpret_cast<std::uint64_t>(host_mapped_address) - host_physical_memory_access_base;
}

/**
 * @description 映射来宾物理地址到宿主线性地址。
 * @param {const cr3} slat_cr3 SLAT CR3。
 * @param {const std::uint64_t} guest_physical_address 来宾物理地址。
 * @param {std::uint64_t* const} size_left_of_page 可选输出页内剩余大小。
 * @return {void*} 映射后的宿主线性地址，失败返回 nullptr。
 * @throws {无} 不抛出异常。
 * @example
 * auto* va = memory_manager::map_guest_physical(slat_cr3, gpa, &size_left);
 */
void* memory_manager::map_guest_physical(const cr3 slat_cr3, const std::uint64_t guest_physical_address, std::uint64_t* const size_left_of_page)
{
	// 业务说明：通过 SLAT 地址转换将来宾物理地址映射到宿主线性地址。
	// 输入：slat_cr3/guest_physical_address；输出：映射地址；规则：转换失败返回 nullptr；异常：不抛出。
	virtual_address_t guest_physical_address_to_map = { };
	guest_physical_address_to_map.address = guest_physical_address;

	const std::uint64_t host_physical_address = slat::translate_guest_physical_address(slat_cr3, guest_physical_address_to_map, size_left_of_page);

	if (!host_physical_address)
	{
		return nullptr;
	}

	return reinterpret_cast<void*>(host_physical_memory_access_base + host_physical_address);
}

/**
 * @description 解析来宾虚拟地址到宿主物理地址。
 * @param {const cr3} guest_cr3 来宾 CR3。
 * @param {const cr3} slat_cr3 SLAT CR3。
 * @param {const virtual_address_t} guest_virtual_address 来宾虚拟地址。
 * @param {std::uint64_t* const} size_left_of_page 可选输出页内剩余大小。
 * @return {std::uint64_t} 宿主物理地址，失败返回 0。
 * @throws {无} 不抛出异常。
 * @example
 * const auto phys = memory_manager::translate_guest_virtual_address(guest_cr3, slat_cr3, gva, &size_left);
 */
std::uint64_t memory_manager::translate_guest_virtual_address(const cr3 guest_cr3, const cr3 slat_cr3, const virtual_address_t guest_virtual_address, std::uint64_t* const size_left_of_page)
{
	// 业务说明：按 PML4/PDPT/PD/PT 逐级解析来宾页表。
	// 输入：guest_cr3/slat_cr3/gva；输出：物理地址；规则：任一层缺失返回 0；异常：不抛出。
	const pml4e_64* pml4 = static_cast<const pml4e_64*>(map_guest_physical(slat_cr3, guest_cr3.address_of_page_directory << 12));
	pml4e_64 pml4e = pml4[guest_virtual_address.pml4_idx];

	if (pml4e.present == 0)
	{
		return 0;
	}

	const pdpte_64* pdpt = static_cast<const pdpte_64*>(map_guest_physical(slat_cr3, pml4e.page_frame_number << 12));
	pdpte_64 pdpte = pdpt[guest_virtual_address.pdpt_idx];

	if (pdpte.present == 0)
	{
		return 0;
	}

	if (pdpte.large_page == 1)
	{
		pdpte_1gb_64 large_pdpte = { };
		large_pdpte.flags = pdpte.flags;
		const std::uint64_t page_offset = (guest_virtual_address.pd_idx << 21) + (guest_virtual_address.pt_idx << 12) + guest_virtual_address.offset;

		if (size_left_of_page != nullptr)
		{
			*size_left_of_page = (1ull << 30) - page_offset;
		}

		return (large_pdpte.page_frame_number << 30) + page_offset;
	}

	const pde_64* pd = static_cast<const pde_64*>(map_guest_physical(slat_cr3, pdpte.page_frame_number << 12));
	pde_64 pde = pd[guest_virtual_address.pd_idx];

	if (pde.present == 0)
	{
		return 0;
	}

	if (pde.large_page == 1)
	{
		pde_2mb_64 large_pde = { };
		large_pde.flags = pde.flags;
		const std::uint64_t page_offset = (guest_virtual_address.pt_idx << 12) + guest_virtual_address.offset;

		if (size_left_of_page != nullptr)
		{
			*size_left_of_page = (1ull << 21) - page_offset;
		}

		return (large_pde.page_frame_number << 21) + page_offset;
	}

	const pte_64* pt = static_cast<const pte_64*>(map_guest_physical(slat_cr3, pde.page_frame_number << 12));
	pte_64 pte = pt[guest_virtual_address.pt_idx];

	if (pte.present == 0)
	{
		return 0;
	}

	const std::uint64_t page_offset = guest_virtual_address.offset;

	if (size_left_of_page != nullptr)
	{
		*size_left_of_page = (1ull << 12) - page_offset;
	}

	return (pte.page_frame_number << 12) + page_offset;
}

/**
 * @description 解析宿主虚拟地址到物理地址。
 * @param {const cr3} host_cr3 宿主 CR3。
 * @param {const virtual_address_t} host_virtual_address 宿主虚拟地址。
 * @param {std::uint64_t* const} size_left_of_page 可选输出页内剩余大小。
 * @return {std::uint64_t} 宿主物理地址，失败返回 0。
 * @throws {无} 不抛出异常。
 * @example
 * const auto phys = memory_manager::translate_host_virtual_address(host_cr3, hva, &size_left);
 */
std::uint64_t memory_manager::translate_host_virtual_address(const cr3 host_cr3, const virtual_address_t host_virtual_address, std::uint64_t* const size_left_of_page)
{
	// 业务说明：按 PML4/PDPT/PD/PT 逐级解析宿主页表。
	// 输入：host_cr3/hva；输出：物理地址；规则：任一层缺失返回 0；异常：不抛出。
	const pml4e_64* pml4 = static_cast<const pml4e_64*>(map_host_physical(host_cr3.address_of_page_directory << 12));
	pml4e_64 pml4e = pml4[host_virtual_address.pml4_idx];

	if (pml4e.present == 0)
	{
		return 0;
	}

	const pdpte_64* pdpt = static_cast<const pdpte_64*>(map_host_physical(pml4e.page_frame_number << 12));
	pdpte_64 pdpte = pdpt[host_virtual_address.pdpt_idx];

	if (pdpte.present == 0)
	{
		return 0;
	}

	if (pdpte.large_page == 1)
	{
		pdpte_1gb_64 large_pdpte = { };
		large_pdpte.flags = pdpte.flags;

		const std::uint64_t page_offset = (host_virtual_address.pd_idx << 21) + (host_virtual_address.pt_idx << 12) + host_virtual_address.offset;

		if (size_left_of_page != nullptr)
		{
			*size_left_of_page = (1ull << 30) - page_offset;
		}

		return (large_pdpte.page_frame_number << 30) + page_offset;
	}

	const pde_64* pd = static_cast<const pde_64*>(map_host_physical(pdpte.page_frame_number << 12));
	pde_64 pde = pd[host_virtual_address.pd_idx];

	if (pde.present == 0)
	{
		return 0;
	}

	if (pde.large_page == 1)
	{
		pde_2mb_64 large_pde = { };
		large_pde.flags = pde.flags;
		const std::uint64_t page_offset = (host_virtual_address.pt_idx << 12) + host_virtual_address.offset;

		if (size_left_of_page != nullptr)
		{
			*size_left_of_page = (1ull << 21) - page_offset;
		}

		return (large_pde.page_frame_number << 21) + page_offset;
	}

	const pte_64* pt = static_cast<const pte_64*>(map_host_physical(pde.page_frame_number << 12));
	pte_64 pte = pt[host_virtual_address.pt_idx];

	if (pte.present == 0)
	{
		return 0;
	}

	const std::uint64_t page_offset = host_virtual_address.offset;

	if (size_left_of_page != nullptr)
	{
		*size_left_of_page = (1ull << 12) - page_offset;
	}

	return (pte.page_frame_number << 12) + page_offset;
}

/**
 * @description 在来宾虚拟内存与宿主缓冲之间读写数据。
 * @param {const cr3} slat_cr3 SLAT CR3。
 * @param {void* const} host_buffer 宿主缓冲区。
 * @param {const std::uint64_t} guest_virtual_address 来宾虚拟地址。
 * @param {const cr3} guest_cr3 来宾 CR3。
 * @param {const std::uint64_t} total_size 读写总大小。
 * @param {const memory_operation_t} operation 读/写类型。
 * @return {std::uint64_t} 实际读写字节数。
 * @throws {无} 不抛出异常。
 * @example
 * const auto bytes = memory_manager::operate_on_guest_virtual_memory(slat_cr3, buffer, gva, guest_cr3, size, memory_operation_t::read_operation);
 */
std::uint64_t memory_manager::operate_on_guest_virtual_memory(const cr3 slat_cr3, void* const host_buffer, const std::uint64_t guest_virtual_address, const cr3 guest_cr3, const std::uint64_t total_size, const memory_operation_t operation)
{
	// 业务说明：逐页转换来宾地址并执行分段拷贝。
	// 输入：slat_cr3/host_buffer/gva/guest_cr3/total_size/operation；输出：完成字节数；规则：地址解析失败终止；异常：不抛出。
	std::uint64_t size_left_to_read = total_size;
	std::uint64_t bytes_read = 0;

	while (size_left_to_read != 0)
	{
		std::uint64_t size_left_of_virtual_page = 0;
		std::uint64_t size_left_of_slat_page = 0;

		virtual_address_t current_guest_virtual_address = { };
		current_guest_virtual_address.address = guest_virtual_address + bytes_read;
		const std::uint64_t guest_physical_address = translate_guest_virtual_address(guest_cr3, slat_cr3, current_guest_virtual_address, &size_left_of_virtual_page);

		if (guest_physical_address == 0)
		{
			break;
		}

		void* guest_physical_mapped = map_guest_physical(slat_cr3, guest_physical_address, &size_left_of_slat_page);
		std::uint8_t* current_host_buffer = static_cast<std::uint8_t*>(host_buffer) + bytes_read;

		const std::uint64_t size_left_of_pages = crt::min(size_left_of_virtual_page, size_left_of_slat_page);
		const std::uint64_t copy_size = crt::min(size_left_to_read, size_left_of_pages);

		if (operation == memory_operation_t::write_operation)
		{
			crt::copy_memory(guest_physical_mapped, current_host_buffer, copy_size);
		}
		else
		{
			crt::copy_memory(current_host_buffer, guest_physical_mapped, copy_size);
		}

		size_left_to_read -= copy_size;
		bytes_read += copy_size;
	}

	return bytes_read;
}

/**
 * @description 修改来宾虚拟地址范围内的页表权限。
 * @param {const cr3} guest_cr3 来宾 CR3。
 * @param {const cr3} slat_cr3 SLAT CR3。
 * @param {const std::uint64_t} guest_base 来宾地址起始基址。
 * @param {const std::uint64_t} offset 基址偏移。
 * @param {const std::uint64_t} size 范围大小。
 * @param {const bool} allow_read 允许读。
 * @param {const bool} allow_write 允许写。
 * @param {const bool} allow_execute 允许执行。
 * @return {bool} 是否修改成功。
 * @throws {无} 不抛出异常。
 * @example
 * const auto ok = memory_manager::set_guest_page_permissions(cr3_value, slat_cr3, base, 0, size, true, true, true);
 */
bool memory_manager::set_guest_page_permissions(const cr3 guest_cr3, const cr3 slat_cr3, const std::uint64_t guest_base, const std::uint64_t offset, const std::uint64_t size, const bool allow_read, const bool allow_write, const bool allow_execute)
{
	// 业务说明：按页遍历来宾页表并更新 PTE 权限位。
	// 输入：guest_cr3/slat_cr3/guest_base/offset/size/allow_*；输出：是否更新成功；规则：遇到无效页表即失败；异常：不抛出。
	if (size == 0)
	{
		return false;
	}

	const std::uint64_t start = guest_base + offset;
	const std::uint64_t end = start + size;
	std::uint64_t current = start;

	while (current < end)
	{
		virtual_address_t gva = { };
		gva.address = current;

		pml4e_64* const pml4 = static_cast<pml4e_64*>(map_guest_physical(slat_cr3, guest_cr3.address_of_page_directory << 12));
		if (pml4 == nullptr)
		{
			return false;
		}

		pml4e_64* const pml4e = &pml4[gva.pml4_idx];
		if (pml4e->present == 0)
		{
			return false;
		}

		pdpte_64* const pdpt = static_cast<pdpte_64*>(map_guest_physical(slat_cr3, pml4e->page_frame_number << 12));
		if (pdpt == nullptr)
		{
			return false;
		}

		pdpte_64* const pdpte = &pdpt[gva.pdpt_idx];
		if (pdpte->present == 0)
		{
			return false;
		}

		if (pdpte->large_page == 1)
		{
			auto* const large_pdpte = reinterpret_cast<pdpte_1gb_64*>(pdpte);
			large_pdpte->present = allow_read ? 1 : 0;
			large_pdpte->write = allow_write ? 1 : 0;
			large_pdpte->execute_disable = allow_execute ? 0 : 1;

			current = (current & ~((1ull << 30) - 1)) + (1ull << 30);
			continue;
		}

		pde_64* const pd = static_cast<pde_64*>(map_guest_physical(slat_cr3, pdpte->page_frame_number << 12));
		if (pd == nullptr)
		{
			return false;
		}

		pde_64* const pde = &pd[gva.pd_idx];
		if (pde->present == 0)
		{
			return false;
		}

		if (pde->large_page == 1)
		{
			auto* const large_pde = reinterpret_cast<pde_2mb_64*>(pde);
			large_pde->present = allow_read ? 1 : 0;
			large_pde->write = allow_write ? 1 : 0;
			large_pde->execute_disable = allow_execute ? 0 : 1;

			current = (current & ~((1ull << 21) - 1)) + (1ull << 21);
			continue;
		}

		pte_64* const pt = static_cast<pte_64*>(map_guest_physical(slat_cr3, pde->page_frame_number << 12));
		if (pt == nullptr)
		{
			return false;
		}

		pte_64* const pte = &pt[gva.pt_idx];
		if (pte->present == 0)
		{
			return false;
		}

		pte->present = allow_read ? 1 : 0;
		pte->write = allow_write ? 1 : 0;
		pte->execute_disable = allow_execute ? 0 : 1;

		current = (current & ~0xFFFull) + 0x1000;
	}

	return true;
}
