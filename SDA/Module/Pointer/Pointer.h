#pragma once
#include <Manager/FunctionManager.h>

namespace CE
{
	class Address
	{
	public:
		Address(void* addr)
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

		static void* Dereference(void* addr, int level)
		{	
			for (int i = 0; i < level; i++) {
				if (!Address(addr).canBeRead())
					return nullptr;
				addr = (void*)*(std::uintptr_t*)addr;
			}
			return addr;
		}

		static void* Dereference(void* addr, CE::Type::Pointer* pointer)
		{
			return Dereference(addr, pointer->getPointerLvl());
		}
	private:
		void* m_addr;
	};

	class Pointer
	{
	public:
		Pointer() {

		}


	};
};