#pragma once
#include "main.h"

namespace CE::Decompiler
{
	class BitMask64 {
		uint64_t m_bitMask = 0x0;
	public:
		BitMask64() = default;

		BitMask64(uint64_t bitMask)
			: m_bitMask(bitMask)
		{}

		BitMask64(int size, int offset = 0x0)
			: BitMask64(GetBitMask64BySize(size) << uint64_t((offset % 8) * 8))
		{}

		uint64_t getValue() const {
			return m_bitMask;
		}

		BitMask64 withoutOffset() {
			return m_bitMask >> getOffset();
		}

		int getBitsCount() const {
			int bitCount = 0;
			for (auto m = m_bitMask; m != 0; m = m >> 1) {
				if (m & 0b1) {
					bitCount++;
				}
			}
			return bitCount;
		}

		int getOffset() const {
			int result = 0;
			for (auto m = m_bitMask; bool(m & 0b1) == 0; m = m >> 1) {
				result += 1;
			}
			return result;
		}

		int getSize() const {
			auto bitsCount = getBitsCount();
			return (bitsCount / 8) + ((bitsCount % 8) ? 1 : 0);
		}

		uint8_t getByteMask8() const {
			uint8_t byteMask8 = 0x0;
			int i = 0;
			for (auto m = m_bitMask; m != 0; m = m >> 8) {
				byteMask8 |= ((m & 0xFF) ? 1 : 0) << (i++);
			}
			return byteMask8;
		}

		BitMask64 operator&(const BitMask64& b) const {
			return m_bitMask & b.m_bitMask;
		}

		BitMask64 operator|(const BitMask64& b) const {
			return m_bitMask | b.m_bitMask;
		}

		BitMask64 operator~() const {
			return ~m_bitMask;
		}

		BitMask64 operator>>(int offset) const {
			return m_bitMask >> offset;
		}

		BitMask64 operator<<(int offset) const {
			return m_bitMask << offset;
		}

		bool operator==(const BitMask64& b) const {
			return m_bitMask == b.m_bitMask;
		}

		bool operator!=(const BitMask64& b) const {
			return !(*this == b);
		}

		bool operator<(const BitMask64& b) const {
			return m_bitMask < b.m_bitMask;
		}

		bool operator<=(const BitMask64& b) const {
			return m_bitMask <= b.m_bitMask;
		}

	private:
		static uint64_t GetBitMask64BySize(int size) {
			if (size == 8)
				return -1;
			return ((uint64_t)1 << (uint64_t)(size * 8)) - 1;
		}
	};

	class ExtBitMask {
		BitMask64 m_bitMask64;
		uint8_t m_index = 0x0;
	public:
		ExtBitMask() = default;

		ExtBitMask(BitMask64 bitMask, uint8_t index)
			: m_bitMask64(bitMask), m_index(index)
		{}

		ExtBitMask(int size, int offset = 0x0)
			: ExtBitMask(BitMask64(size) << int((offset % 8) * 8), uint8_t(offset / 8))
		{}

		ExtBitMask(uint64_t byteMask)
			: ExtBitMask(BitMask64(byteMask).getBitsCount(), BitMask64(byteMask).getOffset())
		{}

		BitMask64 getBitMask64() const {
			return m_bitMask64;
		}

		ExtBitMask operator&(const ExtBitMask& b) const {
			auto resultBitMask = *this;
			resultBitMask.m_bitMask64 = resultBitMask.m_bitMask64 & (m_index == b.m_index ? b.m_bitMask64 : 0);
			return resultBitMask;
		}

		ExtBitMask operator|(const ExtBitMask& b) const {
			auto resultBitMask = *this;
			resultBitMask.m_bitMask64 = resultBitMask.m_bitMask64 | (m_index == b.m_index ? b.m_bitMask64 : 0);
			return resultBitMask;
		}

		ExtBitMask operator~() const {
			auto resultBitMask = *this;
			resultBitMask.m_bitMask64 = ~resultBitMask.m_bitMask64;
			return resultBitMask;
		}

		ExtBitMask operator>>(int offset) const {
			auto resultBitMask = *this;
			resultBitMask.m_bitMask64 = resultBitMask.m_bitMask64 >> (offset % 64);
			resultBitMask.m_index -= offset / 64;
			return resultBitMask;
		}

		ExtBitMask operator<<(int offset) const {
			auto resultBitMask = *this;
			resultBitMask.m_bitMask64 = resultBitMask.m_bitMask64 << (offset % 64);
			resultBitMask.m_index += offset / 64;
			return resultBitMask;
		}

		bool operator==(const ExtBitMask& b) const {
			return m_index == b.m_index && m_bitMask64 == b.m_bitMask64;
		}

		bool operator!=(const ExtBitMask& b) const {
			return !(*this == b);
		}

		bool operator<(const ExtBitMask& b) const {
			if (m_index < b.m_index)
				return true;
			else if (m_index == b.m_index) {
				if (m_bitMask64 < b.m_bitMask64)
					return true;
			}
			return false;
		}

		bool isZero() const {
			return m_bitMask64 == 0x0;
		}

		int getSize() const {
			return m_bitMask64.getSize();
		}

		int getBitsCount() const {
			return m_bitMask64.getBitsCount();
		}

		int getOffset() const {
			return m_bitMask64.getOffset() + m_index * 64;
		}
	};
};