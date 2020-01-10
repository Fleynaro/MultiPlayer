#pragma once
#include <main.h>

class BitStream
{
public:
	BitStream() {
		m_bytes.push_back(0);
	}
	BitStream(BYTE* data, int size) {
		setData(data, size);
	}

	void writeBit(bool bit)
	{
		m_bytes[m_curByte] = m_bytes[m_curByte] & ~(0b1 << m_curBit) | (bit << m_curBit);
		inc();
	}

	template<typename T>
	void write(T value)
	{
		for (int i = 0; i < sizeof(T) * 0x8; i++) {
			writeBit(value >> i & 0b1);
		}
	}

	void write(const void* src, int size) {
		BYTE* data = (BYTE*)src;
		for (int i = 0; i < size; i++)
			write(data[i]);
	}

	bool readBit()
	{
		bool result = m_bytes[m_curByte] >> m_curBit & 0b1;
		inc();
		return result;
	}

	template<typename T>
	T read()
	{
		T result = 0;
		for (int i = 0; i < sizeof(T) * 0x8; i++) {
			result |= readBit() << i;
		}
		return result;
	}

	void read(void* dst, int size) {
		BYTE* data = (BYTE*)dst;
		for (int i = 0; i < size; i++)
			data[i] = read<BYTE>();
	}

	void setData(BYTE* data, int size) {
		for (int i = 0; i < size; i++) {
			m_bytes.push_back(data[i]);
		}
	}

	BYTE* getData() {
		return m_bytes.data();
	}

	int getSize() {
		return m_curByte;
	}

	void resetPointer() {
		m_curByte = 0;
		m_curBit = 0;
	}
private:
	inline void inc() {
		if (++m_curBit == 0x8 * sizeof(BYTE)) {
			m_curByte++;
			m_curBit = 0;
			if (m_curByte == m_bytes.size())
				m_bytes.push_back(0);
		}
	}

	int m_curByte;
	int m_curBit;
	std::vector<BYTE> m_bytes;
};