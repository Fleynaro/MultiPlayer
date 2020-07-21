#pragma once
#include "main.h"

namespace CE::Decompiler
{
	using Mask = uint64_t;

	class INumber
	{
	public:
		virtual Mask getMask() = 0;
	};

	static Mask GetMaskWithException(Mask mask) {
		if (mask == 0xFFFFFFFF)
			return 0xFFFFFFFFFFFFFFFF;
		return mask;
	}

	static int GetShiftValueOfMask(Mask mask) {
		int result = 0;
		for (auto m = mask; bool(m & 0b1) == 0; m = m >> 1) {
			result += 1;
		}
		return result;
	}

	static int GetBitCountOfMask(Mask mask, bool onlyOne = true) {
		int result = 0;
		for (auto m = mask; m != 0; m = m >> 1) {
			if (!onlyOne || (m & 0b1)) {
				result++;
			}
		}
		return result;
	}

	static Mask GetMaskBySize(int size, bool byteAsBit = true) {
		auto k = byteAsBit ? 1 : 8;
		if (size == 64 / k)
			return -1;
		return ((uint64_t)1 << (uint64_t)(size * k)) - 1;
	}

	static uint64_t GetMask64ByMask(Mask mask) {
		uint64_t value = 0x0;
		for (int i = 0; i < 8; i ++) {
			value |= (((mask >> i) & 0b1) * 0xFF) << (i * 8);
		}
		return value;
	}

	static Mask GetMaskByMask64(uint64_t value) {
		Mask mask = 0x0;
		int i = 0;
		for (auto val = value; val != 0; val = val >> 8) {
			mask |= ((val & 0xFF) ? 1 : 0) << (i++);
		}
		return mask;
	}
};