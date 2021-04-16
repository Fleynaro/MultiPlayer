#pragma once
#include "main.h"

namespace CE
{
	class IImage {
	public:
		virtual byte* getData() = 0;
		virtual int getSize() = 0;
		virtual int getOffsetOfEntryPoint() = 0;
		virtual bool containCode(int offset) {
			return true;
		}
	};
};