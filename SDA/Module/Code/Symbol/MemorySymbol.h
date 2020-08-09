#pragma once
#include "AbstractSymbol.h"

namespace CE::Symbol
{
	class MemoryArea;

	class MemorySymbol : public AbstractSymbol
	{
	public:
		MemorySymbol(SymbolManager* manager, DataTypePtr type, const std::string& name, const std::string& comment = "")
			: AbstractSymbol(manager, type, name, comment)
		{}

		virtual int getSize() {
			return getDataType()->getSize();
		}

		MemoryArea* getMemoryArea() {
			return m_memoryArea;
		}

		void setMemoryArea(MemoryArea* memoryArea) {
			m_memoryArea = memoryArea;
		}
	private:
		MemoryArea* m_memoryArea = nullptr;
	};
};