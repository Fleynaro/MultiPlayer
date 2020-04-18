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

		bool canBeRead();

		HMODULE getModuleHandle();

		MEMORY_BASIC_INFORMATION getInfo();

		void* getAddress() {
			return m_addr;
		}

		Address dereference();

		template<typename T>
		T& get();

		enum ProtectFlags {
			No			= 0,
			Read		= 1,
			Write		= 2,
			Execute		= 4
		};

		void setProtect(ProtectFlags flags, int size = 1);

		ProtectFlags getProtect();

		static void* Dereference(void* addr, int level);
	private:
		void* m_addr;
	};


	template<typename T>
	inline T& Address::get() {
		return *(T*)m_addr;
	}
};