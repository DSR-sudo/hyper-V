#include "crt.h"
#include <intrin.h>

void crt::copy_memory(void* const destination, const void* const source, const std::uint64_t size)
{
	__movsb(static_cast<std::uint8_t*>(destination), static_cast<const std::uint8_t*>(source), size);
}

void crt::set_memory(void* const destination, const std::uint8_t value, const std::uint64_t size)
{
	__stosb(static_cast<std::uint8_t*>(destination), value, size);
}

// Forward declarations with C linkage
extern "C" void* __cdecl memset(void*, int, unsigned __int64);
extern "C" void* __cdecl memcpy(void*, const void*, unsigned __int64);

#pragma function(memset, memcpy)

extern "C" void* __cdecl memset(void* dest, int val, unsigned __int64 count)
{
	crt::set_memory(dest, static_cast<std::uint8_t>(val), count);
	return dest;
}

extern "C" void* __cdecl memcpy(void* dest, const void* src, unsigned __int64 count)
{
	crt::copy_memory(dest, src, count);
	return dest;
}

void crt::mutex_t::lock()
{
	while (_InterlockedCompareExchange64(&value_, 1, 0) != 0)
	{
		_mm_pause();
	}
}

bool crt::mutex_t::try_lock()
{
	return _InterlockedCompareExchange64(&value_, 1, 0) == 0;
}

void crt::mutex_t::release()
{
	_InterlockedExchange64(&value_, 0);
}

void crt::bitmap_t::set_all() const
{
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

void crt::bitmap_t::set(const value_type index) const
{
    const pointer target_row = row(index);

    if (target_row == nullptr)
    {
        return;
    }

    const std::uint64_t bit = index % bit_count_in_row;

    *target_row |= 1ull << bit;
}

void crt::bitmap_t::clear(const value_type index) const
{
    const pointer target_row = row(index);

    if (target_row == nullptr)
    {
        return;
    }

    const size_type bit = index % bit_count_in_row;

    *target_row &= ~(1ull << bit);
}

crt::bitmap_t::bit_type crt::bitmap_t::is_set(const value_type index) const
{
    const const_pointer target_row = row(index);

    if (target_row == nullptr)
    {
        return 0;
    }

    const value_type row_value = *target_row;
    const size_type bit = index % bit_count_in_row;

    return (row_value >> bit) & 1;
}

void crt::bitmap_t::set_value(const pointer value)
{
    value_ = value;
}
	
void crt::bitmap_t::set_count(const size_type value_count)
{
    count_ = value_count;
}

crt::bitmap_t::pointer crt::bitmap_t::row(const value_type index) const
{
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
