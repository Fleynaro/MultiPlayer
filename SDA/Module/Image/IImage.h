#pragma once
#include "main.h"

namespace CE
{
	class IImage {
	public:
		virtual byte* getData() = 0;

		virtual int getSize() = 0;

		virtual int getOffsetOfEntryPoint() = 0;

		virtual DWORD toImageOffset(DWORD rva) {
			return rva;
		}

		virtual bool containCode(int offset) {
			return true;
		}
	};
};