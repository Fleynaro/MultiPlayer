#pragma once
#include "main.h"

namespace CE::Decompiler
{
	/*using Mask = uint64_t;*/

	//todo: mask is bits and an offset, it is enough
	class BitMask {
		uint64_t m_bitMask[4] = { 0x0, 0x0, 0x0, 0x0 };
	public:
		BitMask() = default;

		BitMask(uint64_t bitMask[4])
		{
			m_bitMask[0] = bitMask[0];
			m_bitMask[1] = bitMask[1];
			m_bitMask[2] = bitMask[2];
			m_bitMask[3] = bitMask[3];
		}

		BitMask(uint64_t byteMask)
		{
			for (int i = 0; i < 4; i++) {
				m_bitMask[i] = GetBitMask64ByByteMask8((byteMask >> (i * 8)) & 0xFF);
			}
		}

		BitMask(int size, int offset = 0x0)
			: BitMask(GetByteMaskBySize(size) << offset)
		{}

		uint64_t getBitMask64() const {
			return m_bitMask[0];
		}

		BitMask operator&(const BitMask& b) const {
			auto resultBitMask = *this;
			resultBitMask.m_bitMask[0] &= b.m_bitMask[0];
			resultBitMask.m_bitMask[1] &= b.m_bitMask[1];
			resultBitMask.m_bitMask[2] &= b.m_bitMask[2];
			resultBitMask.m_bitMask[3] &= b.m_bitMask[3];
			return resultBitMask;
		}

		BitMask operator|(const BitMask& b) const {
			auto resultBitMask = *this;
			resultBitMask.m_bitMask[0] |= b.m_bitMask[0];
			resultBitMask.m_bitMask[1] |= b.m_bitMask[1];
			resultBitMask.m_bitMask[2] |= b.m_bitMask[2];
			resultBitMask.m_bitMask[3] |= b.m_bitMask[3];
			return resultBitMask;
		}

		BitMask operator^(const BitMask& b) const {
			auto resultBitMask = *this;
			resultBitMask.m_bitMask[0] ^= b.m_bitMask[0];
			resultBitMask.m_bitMask[1] ^= b.m_bitMask[1];
			resultBitMask.m_bitMask[2] ^= b.m_bitMask[2];
			resultBitMask.m_bitMask[3] ^= b.m_bitMask[3];
			return resultBitMask;
		}

		BitMask operator~() const {
			auto resultBitMask = *this;
			resultBitMask.m_bitMask[0] = ~resultBitMask.m_bitMask[0];
			resultBitMask.m_bitMask[1] = ~resultBitMask.m_bitMask[1];
			resultBitMask.m_bitMask[2] = ~resultBitMask.m_bitMask[2];
			resultBitMask.m_bitMask[3] = ~resultBitMask.m_bitMask[3];
			return resultBitMask;
		}

		bool operator==(const BitMask& b) const {
			return m_bitMask[0] == b.m_bitMask[0]
				&& m_bitMask[1] == b.m_bitMask[1]
				&& m_bitMask[2] == b.m_bitMask[2]
				&& m_bitMask[3] == b.m_bitMask[3];
		}

		bool operator!=(const BitMask& b) const {
			return !(*this == b);
		}

		bool operator<(const BitMask& b) const {
			if (m_bitMask[3] < b.m_bitMask[3])
				return true;
			else if (m_bitMask[3] == b.m_bitMask[3]) {
				if (m_bitMask[2] < b.m_bitMask[2])
					return true;
				else if (m_bitMask[2] == b.m_bitMask[2]) {
					if (m_bitMask[1] < b.m_bitMask[1])
						return true;
					else if (m_bitMask[1] == b.m_bitMask[1]) {
						if (m_bitMask[0] < b.m_bitMask[0])
							return true;
					}
				}
			}
			return false;
		}

		uint64_t operator>>(int offset) const {
			return m_bitMask[offset / 64] >> (offset % 64);
		}

		bool isZero() const {
			return (m_bitMask[0] | m_bitMask[1] | m_bitMask[2] | m_bitMask[3]) == 0x0;
		}

		int getSize() const {
			auto bitsCount = getBitsCount();
			return (bitsCount / 8) + ((bitsCount % 8) ? 0 : 1);
		}

		int getBitsCount() const {
			int result = 0;
			for (int i = 0; i < 4; i++) {
				if (m_bitMask[i] != 0x0)
					result += GetBitsCountOfMask64(m_bitMask[0]);
			}
			return result;
		}

		int getOffset() const {
			for (int i = 0; i < 4; i++) {
				if (m_bitMask[i] != 0x0)
					return GetOffsetOfMask64(m_bitMask[i]) + 64 * i;
			}
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

		static uint64_t GetBitMask64ByByteMask8(uint64_t byteMask8) {
			uint64_t bitMask64 = 0x0;
			for (int i = 0; i < 8; i++) {
				bitMask64 |= (((byteMask8 >> i) & 0b1) * 0xFF) << (i * 8);
			}
			return bitMask64;
		}

		static uint64_t GetByteMask8ByBitMask64(uint64_t bitMask64) {
			uint64_t byteMask8 = 0x0;
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
		if (mask == uint64_t(0b1111))
			return uint64_t(0b11111111);
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