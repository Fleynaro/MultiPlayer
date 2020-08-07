#pragma once
#include "main.h"

namespace CE::Decompiler
{
	/*using Mask = uint64_t;*/

	//todo: mask is bits and an offset, it is enough
	class BitMask {
		uint64_t m_bitMask = 0x0;
		uint8_t m_index = 0x0;
	public:
		BitMask() = default;

		BitMask(uint64_t bitMask, uint8_t index)
			: m_bitMask(bitMask), m_index(index)
		{}

		BitMask(int size, int offset = 0x0)
			: BitMask(GetBitMask64BySize(size) << uint64_t((offset % 8) * 8), uint8_t(offset / 8))
		{}

		BitMask(uint64_t byteMask)
			: BitMask(GetBitsCountOfMask64(byteMask), GetOffsetOfMask64(byteMask))
		{}

		uint64_t getBitMask64() const {
			return m_bitMask;
		}

		BitMask operator&(const BitMask& b) const {
			auto resultBitMask = *this;
			resultBitMask.m_bitMask &= (m_index == b.m_index ? b.m_bitMask : 0);
			return resultBitMask;
		}

		BitMask operator|(const BitMask& b) const {
			auto resultBitMask = *this;
			resultBitMask.m_bitMask |= (m_index == b.m_index ? b.m_bitMask : 0);
			return resultBitMask;
		}

		BitMask operator^(const BitMask& b) const {
			auto resultBitMask = *this;
			resultBitMask.m_bitMask ^= (m_index == b.m_index ? b.m_bitMask : 0);
			return resultBitMask;
		}

		BitMask operator~() const {
			auto resultBitMask = *this;
			resultBitMask.m_bitMask = ~resultBitMask.m_bitMask;
			return resultBitMask;
		}

		BitMask operator>>(int offset) const {
			auto resultBitMask = *this;
			resultBitMask.m_bitMask >>= offset % 64;
			resultBitMask.m_index -= offset / 64;
			return resultBitMask;
		}

		BitMask operator<<(int offset) const {
			auto resultBitMask = *this;
			resultBitMask.m_bitMask <<= offset % 64;
			resultBitMask.m_index += offset / 64;
			return resultBitMask;
		}

		bool operator==(const BitMask& b) const {
			return m_index == b.m_index && m_bitMask == b.m_bitMask;
		}

		bool operator!=(const BitMask& b) const {
			return !(*this == b);
		}

		bool operator<(const BitMask& b) const {
			if (m_index < b.m_index)
				return true;
			else if (m_index == b.m_index) {
				if (m_bitMask < b.m_bitMask)
					return true;
			}
			return false;
		}

		bool isZero() const {
			return m_bitMask == 0x0;
		}

		int getSize() const {
			auto bitsCount = getBitsCount();
			return (bitsCount / 8) + ((bitsCount % 8) ? 1 : 0);
		}

		int getBitsCount() const {
			return GetBitsCountOfMask64(m_bitMask);
		}

		int getOffset() const {
			return GetOffsetOfMask64(m_bitMask) + m_index * 64;
		}

		static int GetBitsCountOfMask64(uint64_t bitMask64) {
			int bitCount = 0;
			for (auto m = bitMask64; m != 0; m = m >> 1) {
				if (m & 0b1) {
					bitCount++;
				}
			}
			return bitCount;
		}

		static int GetOffsetOfMask64(uint64_t bitMask64) {
			int result = 0;
			for (auto m = bitMask64; bool(m & 0b1) == 0; m = m >> 1) {
				result += 1;
			}
			return result;
		}

		static uint64_t GetBitMask64ByByteMask8(uint8_t byteMask8) {
			uint64_t bitMask64 = 0x0;
			for (int i = 0; i < 8; i++) {
				bitMask64 |= (((byteMask8 >> i) & 0b1) * 0xFF) << (i * 8);
			}
			return bitMask64;
		}

		static uint8_t GetByteMask8ByBitMask64(uint64_t bitMask64) {
			uint8_t byteMask8 = 0x0;
			int i = 0;
			for (auto m = bitMask64; m != 0; m = m >> 8) {
				byteMask8 |= ((m & 0xFF) ? 1 : 0) << (i++);
			}
			return byteMask8;
		}

		static uint64_t GetBitMask64BySize(int size) {
			if (size == 8)
				return -1;
			return ((uint64_t)1 << (uint64_t)(size * 8)) - 1;
		}

		static uint64_t GetByteMaskBySize(int size) {
			if (size == 64)
				return -1;
			return ((uint64_t)1 << (uint64_t)size) - 1;
		}

	};

	class INumber
	{
	public:
		virtual BitMask getMask() = 0;
	};

	static BitMask GetMaskWithException(BitMask& mask) {
		if (mask == BitMask(4))
			return BitMask(8);
		return mask;
	}

	/*
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
	}*/
};