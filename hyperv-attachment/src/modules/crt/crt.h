#pragma once
#include <cstdint>

namespace crt
{
	void copy_memory(void* destination, const void* source, std::uint64_t size);
	void set_memory(void* destination, std::uint8_t value, std::uint64_t size);

	/**
	 * @description 计算字符串长度。
	 * @param {const char*} string 输入字符串。
	 * @return {std::uint64_t} 字符串长度。
	 * @throws {无} 不抛出异常。
	 * @example
	 * const auto len = crt::string_length("test");
	 */
	std::uint64_t string_length(const char* string);

	/**
	 * @description 比较两个字符串是否相等。
	 * @param {const char*} s1 第一个字符串。
	 * @param {const char*} s2 第二个字符串。
	 * @return {bool} 如果相等返回 true，否则返回 false。
	 * @throws {无} 不抛出异常。
	 * @example
	 * if (crt::string_compare("test", "test")) { ... }
	 */
	bool string_compare(const char* s1, const char* s2);

	/**
	 * @description 获取两个值中的较小值。
	 * @param {const T} a 第一个值。
	 * @param {const T} b 第二个值。
	 * @return {T} 较小值。
	 * @throws {无} 不抛出异常。
	 * @example
	 * const auto v = crt::min(1, 2);
	 */
	template <class T>
	T min(const T a, const T b)
	{
		return (a < b) ? a : b;
	}

	/**
	 * @description 获取两个值中的较大值。
	 * @param {const T} a 第一个值。
	 * @param {const T} b 第二个值。
	 * @return {T} 较大值。
	 * @throws {无} 不抛出异常。
	 * @example
	 * const auto v = crt::max(1, 2);
	 */
	template <class T>
	T max(const T a, const T b)
	{
		return (a < b) ? b : a;
	}

	/**
	 * @description 计算绝对值。
	 * @param {const T} n 输入值。
	 * @return {T} 绝对值结果。
	 * @throws {无} 不抛出异常。
	 * @example
	 * const auto v = crt::abs(-1);
	 */
	template <class T>
	T abs(const T n)
	{
		return (n < 0) ? -n : n;
	}

	/**
	 * @description 交换两个值。
	 * @param {T&} a 第一个值引用。
	 * @param {T&} b 第二个值引用。
	 * @return {void} 无返回值。
	 * @throws {无} 不抛出异常。
	 * @example
	 * crt::swap(a, b);
	 */
	template <class T>
	void swap(T& a, T& b) noexcept
	{
		const T cache = a;

		a = b;
		b = cache;
	}

	class mutex_t
	{
	public:
		void lock();
		bool try_lock();
		void release();

	protected:
		volatile std::int64_t value_;
	};

	class bitmap_t
	{
	public:
		using size_type = std::uint64_t;

		using value_type = std::uint64_t;
		using pointer = value_type*;
		using const_pointer = const value_type*;

		using bit_type = std::uint8_t;

		/**
		 * @description 创建位图对象。
		 * @param {void} 无。
		 * @return {void} 无返回值。
		 * @throws {无} 不抛出异常。
		 * @example
		 * crt::bitmap_t map;
		 */
		bitmap_t() = default;

		void set_all() const;
		void set(value_type index) const;

		void clear(value_type index) const;

		[[nodiscard]] bit_type is_set(value_type index) const;

		void set_value(pointer value);
		void set_count(size_type value_count);

	protected:
		constexpr static size_type bit_count_in_row = sizeof(value_type) * 8;
		constexpr static value_type value_max = ~static_cast<value_type>(0);

		pointer value_;
		size_type count_;

		[[nodiscard]] pointer row(value_type index) const;
	};
}
