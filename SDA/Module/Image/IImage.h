#pragma once
#include "main.h"

namespace CE
{
	class IImage {
	public:
		enum SegmentType {
			NONE_SEGMENT,
			CODE_SEGMENT,
			DATA_SEGMENT
		};

		virtual byte* getData() = 0;

		virtual int getSize() = 0;

		virtual int getOffsetOfEntryPoint() = 0;

		virtual int toImageOffset(int offset) {
			return offset;
		}

		virtual SegmentType defineSegment(int offset) {
			return NONE_SEGMENT;
		}
	};
};