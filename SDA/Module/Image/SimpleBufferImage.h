#pragma once
#include "IImage.h"

namespace CE
{
	class SimpelBufferImage : public IImage
	{
		byte* m_data;
		int m_size;
	public:
		SimpelBufferImage(byte* data, int size)
			: m_data(data), m_size(size)
		{}

		byte* getData() override {
			return m_data;
		}

		int getSize() override {
			return m_size;
		}

		int getOffsetOfEntryPoint() override {
			return 0;
		}
	};
};