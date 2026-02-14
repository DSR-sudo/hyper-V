#pragma once
#include <cstdint>
#include "../slat.h"

namespace slat::violation
{
	std::uint8_t process(context_t* ctx);
	void handle_mtf(context_t* ctx);
}
