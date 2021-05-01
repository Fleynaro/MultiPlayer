#pragma once
#include "AbstractSymbol.h"
#include "IMemorySymbol.h"

namespace CE::Symbol
{
	class SymbolTable;

	class GlobalVarSymbol : public AbstractSymbol, public IMemorySymbol
	{
		int64_t m_offset;
	public:
		GlobalVarSymbol(SymbolManager* manager, int64_t offset, DataTypePtr type, const std::string& name, const std::string& comment = "")
			: AbstractSymbol(manager, type, name, comment), m_offset(offset)
		{}

		Type getType() override {
			return GLOBAL_VAR;
		}

		Decompiler::Storage getStorage() override {
			return Decompiler::Storage(Decompiler::Storage::STORAGE_GLOBAL, 0, m_offset);
		}
	};

	class LocalStackVarSymbol : public AbstractSymbol, public IMemorySymbol
	{
		int64_t m_offset;
	public:
		LocalStackVarSymbol(SymbolManager* manager, int64_t offset, DataTypePtr type, const std::string& name, const std::string& comment = "")
			: AbstractSymbol(manager, type, name, comment), m_offset(offset)
		{}

		Type getType() override {
			return LOCAL_STACK_VAR;
		}

		Decompiler::Storage getStorage() override {
			return Decompiler::Storage(Decompiler::Storage::STORAGE_STACK, 0, m_offset);
		}
	};
};