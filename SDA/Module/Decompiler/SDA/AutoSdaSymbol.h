#pragma once
#include <Code/Symbol/AbstractSymbol.h>

namespace CE::Symbol
{
	// high-level not-memory symbol created by decompiler automatically (e.g. localVar1, funcVar1, ...)
	class AutoSdaSymbol : public AbstractSymbol
	{
		Type m_type;
		int64_t m_value;
		std::list<int64_t> m_instrOffsets;
	public:
		AutoSdaSymbol(Type type, int64_t value, std::list<int64_t> instrOffsets, SymbolManager* manager, DataTypePtr dataType, const std::string& name, const std::string& comment = "")
			: m_type(type), m_value(value), m_instrOffsets(instrOffsets), AbstractSymbol(manager, dataType, name, comment)
		{}

		Type getType() override {
			return m_type;
		}

		std::list<int64_t> getInstrOffsets() {
			return m_instrOffsets;
		}
	};

	// high-level memory symbol created by decompiler automatically (stackVar or globalVar)
	class AutoSdaMemSymbol : public AutoSdaSymbol, public IMemorySymbol
	{
		int64_t m_offset;
	public:
		AutoSdaMemSymbol(Type type, int64_t offset, std::list<int64_t> instrOffsets, SymbolManager* manager, DataTypePtr dataType, const std::string& name, const std::string& comment = "")
			: AutoSdaSymbol(type, 0, instrOffsets, manager, dataType, name, comment), m_offset(offset)
		{}

		std::list<Decompiler::Storage> getStorages() override {
			if (getType() == LOCAL_STACK_VAR)
				return { Decompiler::Storage(Decompiler::Storage::STORAGE_STACK, 0, m_offset) };
			if (getType() == GLOBAL_VAR)
				return { Decompiler::Storage(Decompiler::Storage::STORAGE_GLOBAL, 0, m_offset) };
			return {};
		}
	};
};