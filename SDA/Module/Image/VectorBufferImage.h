#pragma once
#include "IImage.h"

namespace CE
{
	class VectorBufferImage : public IImage
	{
		std::vector<byte> m_content;
	public:
		VectorBufferImage(std::vector<byte> content)
			: m_content(content)
		{}

		byte* getData() override {
			return m_content.data();
		}

		int getSize() override {
			return (int)m_content.size();
		}

		int getOffsetOfEntryPoint() override {
			return 0;
		}

		SegmentType defineSegment(int offset) override {
			return CODE_SEGMENT;
		}
	};
};