#pragma once
#include "AbstractSymbol.h"
#include "IMemorySymbol.h"

namespace CE::Symbol
{
	class MemoryArea;

	class MemorySymbol : public AbstractSymbol
	{
	public:
		MemoryArea* m_memoryArea = nullptr;
		std::list<int64_t> m_offsets;

		MemorySymbol(SymbolManager* manager, DataTypePtr type, const std::string& name, const std::string& comment = "")
			: AbstractSymbol(manager, type, name, comment)
		{}

		virtual int getSize() {
			return getDataType()->getSize();
		}

		MemoryArea* getMemoryArea() {
			return m_memoryArea;
		}
	};

	class GlobalVarSymbol : public MemorySymbol, public IMemorySymbol
	{
	public:
		GlobalVarSymbol(SymbolManager* manager, DataTypePtr type, const std::string& name, const std::string& comment = "")
			: MemorySymbol(manager, type, name, comment)
		{}

		Type getType() override {
			return GLOBAL_VAR;
		}

		std::list<Decompiler::Storage> getStorages() override {
			return { Decompiler::Storage(Decompiler::Storage::STORAGE_GLOBAL, 0, *m_offsets.begin()) };
		}
	};

	class LocalStackVarSymbol : public MemorySymbol, public IMemorySymbol
	{
	public:
		LocalStackVarSymbol(SymbolManager* manager, DataTypePtr type, const std::string& name, const std::string& comment = "")
			: MemorySymbol(manager, type, name, comment)
		{}

		Type getType() override {
			return LOCAL_STACK_VAR;
		}

		std::list<Decompiler::Storage> getStorages() override {
			return { Decompiler::Storage(Decompiler::Storage::STORAGE_STACK, 0, *m_offsets.begin()) };
		}
	};

	class LocalInstrVarSymbol : public MemorySymbol
	{
	public:
		LocalInstrVarSymbol(SymbolManager* manager, DataTypePtr type, const std::string& name, const std::string& comment = "")
			: MemorySymbol(manager, type, name, comment)
		{}

		Type getType() override {
			return LOCAL_INSTR_VAR;
		}
	};
};