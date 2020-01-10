#pragma once

#include "MemoryHandle.h"



namespace Memory
{
	template<typename T>
	class IDynStructure
	{
	public:
		using fieldList = std::vector<Offset>;

		IDynStructure(Handle base) : m_base(base)
		{
			firstInit();
		}

		IDynStructure(void* base) : IDynStructure(Handle(base)) {}
		
		//init only once
		static void firstInit()
		{
			static bool inited = false;
			if (!inited) {
				T::m_offsets.reserve(100);
				inited = true;
				
				//check on exitst
				T::init();
			}
		}

		//get base address of the structure
		virtual Handle getBase()
		{
			return m_base;
		}

		//get field handle
		Handle getField(std::size_t index)
		{
			return getBase().add(getFieldOffset(index));
		}

		//get pointer from field
		template<typename T>
		T getFieldPtr(std::size_t index)
		{
			return getField(index).as<T>();
		}

		//get value from field
		template<typename T>
		T getFieldValue(std::size_t index)
		{
			return getField(index).get<T>();
		}

		//get value from field
		template<typename T>
		void setFieldValue(std::size_t index, T *data, std::size_t size = sizeof(T))
		{
			getField(index).set(data, size);
		}

		//add offset(relative of base) to the offset list
		static void addFieldOffset(Offset offset)
		{
			T::m_offsets.push_back(offset);
		}

		//set offset(relative of base) to the field of the offset list
		static void setFieldOffset(std::size_t index, Offset offset)
		{
			T::m_offsets[index] = offset;
		}

		//get field offset(relative of base)
		static Offset getFieldOffset(std::size_t index)
		{
			return T::m_offsets[index];
		}

		IDynStructure& operator=(const void* data)
		{
			m_base = Handle(data);
			firstInit();
			return *this;
		}
	protected:
		Handle m_base = nullptr;
		inline static Memory::IDynStructure<T>::fieldList m_offsets;
	};


	template<typename T>
	class IDynStructureVT : public IDynStructure<T>
	{
		using superClass = IDynStructure<T>;
	public:
		using vtfList = std::vector<Offset>;
		IDynStructureVT(Handle base) : superClass(base) {}
		IDynStructureVT(void* base) : IDynStructureVT(Handle(base)) {}

		//get address of the virtual table
		Handle getVTable()
		{
			return superClass::getBase().dereference();
		}

		//get virtual function
		Handle getVirtualFunction(std::size_t index)
		{
			return getVTable().add(
				getVTFieldOffset(index)
			).dereference();
		}

		//set virtual function
		void setVirtualFunction(std::size_t index, void* func)
		{
			std::uintptr_t f = (std::uintptr_t)func;
			getVTable().add(
				getVTFieldOffset(index)
			).set(&f, sizeof(std::uintptr_t));
		}

		//add offset(relative of base) to the offset vtf list
		static void addVTFieldOffset(Offset offset)
		{
			T::m_vt_offsets.push_back(offset);
		}

		//set offset(relative of base) to the vt field of the vtf list
		static void setVTFieldOffset(std::size_t index, Offset offset)
		{
			T::m_vt_offsets[index] = offset;
		}

		//set index to the vt field of the vtf list
		static void setVTFieldIndex(std::size_t index, std::size_t index2)
		{
			setVTFieldOffset(index, index2 * sizeof(std::uintptr_t));
		}

		//get vt field offset(relative of base)
		static Offset getVTFieldOffset(std::size_t index)
		{
			return T::m_vt_offsets[index];
		}

		//get vt field index
		static Offset getVTFieldIndex(std::size_t index)
		{
			return getVTFieldOffset(index) / sizeof(std::uintptr_t);
		}
	protected:
		inline static Memory::IDynStructureVT<T>::vtfList m_vt_offsets;
	};
};