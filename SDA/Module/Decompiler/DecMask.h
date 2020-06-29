#pragma once
#include "main.h"

namespace CE::Decompiler
{
	class INumber
	{
	public:
		virtual uint64_t getMask() = 0;
	};

	static int GetShiftValueOfMask(uint64_t mask) {
		int result = 0;
		for (auto m = mask; int(m & 0xF) == 0; m = m >> 4) {
			result += 4;
		}
		return result;
	}

	static int GetBitCountOfMask(uint64_t mask) {
		int result = 0;
		for (auto m = mask; m != 0; m = m >> 1) {
			result++;
		}
		return result;
	}

	static uint64_t GetMaskBySize(int size) {
		if (size == 8)
			return -1;
		return ((uint64_t)1 << (uint64_t)(size * 8)) - 1;
	}
};