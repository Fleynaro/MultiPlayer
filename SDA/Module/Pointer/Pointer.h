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

		enum ProtectFlags {
			No			= 0,
			Read		= 1,
			Write		= 2,
			Execute		= 4
		};

		void setProtect(ProtectFlags flags) {
			DWORD new_ = PAGE_NOACCESS;
			DWORD old_;

			switch (flags)
			{
			case Read:
				new_ = PAGE_READONLY;
				break;
			case Write:
			case Read | Write:
				new_ = PAGE_READWRITE;
				break;
			case Execute:
				new_ = PAGE_EXECUTE;
				break;
			case Execute | Read:
				new_ = PAGE_EXECUTE_READ;
				break;
			case Execute | Write:
			case Execute | Read | Write:
				new_ = PAGE_EXECUTE_READWRITE;
				break;
			}

			VirtualProtect(m_addr, 1, new_, &old_);
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
};