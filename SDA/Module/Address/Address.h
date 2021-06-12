#pragma once
#include <main.h>
#include <Code/Type/TypeUnit.h>
#include <Utils/Iterator.h>

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

		void addOffset(int offset);

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

	using DereferenceIteratorItemType = std::pair<void*, DataType::AbstractType*>;
	class DereferenceIterator : public IIterator<DereferenceIteratorItemType>
	{
	public:
		DereferenceIterator(Address addr, DataTypePtr type);

		bool hasNext() override;

		DereferenceIteratorItemType next() override;
	private:
		Address m_addr;
		Address m_curAddr;
		DataTypePtr m_type;
		std::list<int> m_levels;
		std::list<int> m_cur_levels;
		bool m_isEnd = false;

		void goNext();

		Address dereference();
	};
};