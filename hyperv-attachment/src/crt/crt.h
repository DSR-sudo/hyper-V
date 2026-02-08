#pragma once
#include <cstdint>

namespace crt
{
	void copy_memory(void* destination, const void* source, std::uint64_t size);
	void set_memory(void* destination, std::uint8_t value, std::uint64_t size);

	template <class T>
	T min(const T a, const T b)
	{
		return (a < b) ? a : b;
	}

	template <class T>
	T max(const T a, const T b)
	{
		return (a < b) ? b : a;
	}

	template <class T>
	T abs(const T n)
	{
		return (n < 0) ? -n : n;
	}

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
		volatile std::int64_t value_ = 0;
	};

	class bitmap_t
	{
	public:
		using size_type = std::uint64_t;

		using value_type = std::uint64_t;
		using pointer = value_type*;
		using const_pointer = const value_type*;

		using bit_type = std::uint8_t;

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

		pointer value_ = nullptr;
		size_type count_ = 0;

		[[nodiscard]] pointer row(value_type index) const;
	};
}
