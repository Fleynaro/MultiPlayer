#pragma once
#include <Manager/FunctionManager.h>

namespace CE
{
	class Pointer
	{
	public:
		Pointer(void* addr)
			: m_addr(addr)
		{}

		bool canBeRead() {
			__try {
				byte firstByte = *(byte*)m_addr;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return false;
			}
			return true;
		}

		HMODULE getModuleHandle() {
			MEMORY_BASIC_INFORMATION mbi;
			VirtualQuery(m_addr, &mbi, sizeof(mbi));
			return (HMODULE)mbi.AllocationBase;
		}

		void* getAddress() {
			return m_addr;
		}
	private:
		void* m_addr;
	};
};