#pragma once
#include "AbstractSymbol.h"
#include "IMemorySymbol.h"

namespace CE::Symbol
{
	class SymbolTable;

	class MemorySymbol : public AbstractSymbol, public IMemorySymbol
	{
		int64_t m_offset;
	public:
		MemorySymbol(SymbolManager* manager, int64_t offset, DataTypePtr type, const std::string& name, const std::string& comment = "")
			: AbstractSymbol(manager, type, name, comment), m_offset(offset)
		{}

		int64_t getOffset() {
			return m_offset;
		}

		void setOffset(int64_t offset) {
			m_offset = offset;
		}
	};

	class GlobalVarSymbol : public MemorySymbol
	{
	public:
		GlobalVarSymbol(SymbolManager* manager, int64_t offset, DataTypePtr type, const std::string& name, const std::string& comment = "")
			: MemorySymbol(manager, offset, type, name, comment)
		{}

		Type getType() override {
			return GLOBAL_VAR;
		}

		Decompiler::Storage getStorage() override {
			return Decompiler::Storage(Decompiler::Storage::STORAGE_GLOBAL, 0, getOffset());
		}
	};

	class LocalStackVarSymbol : public MemorySymbol
	{
	public:
		LocalStackVarSymbol(SymbolManager* manager, int64_t offset, DataTypePtr type, const std::string& name, const std::string& comment = "")
			: MemorySymbol(manager, offset, type, name, comment)
		{}

		Type getType() override {
			return LOCAL_STACK_VAR;
		}

		Decompiler::Storage getStorage() override {
			return Decompiler::Storage(Decompiler::Storage::STORAGE_STACK, 0, getOffset());
		}
	};
};