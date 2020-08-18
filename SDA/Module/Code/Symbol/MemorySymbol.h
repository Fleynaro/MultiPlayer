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

	class FunctionSymbol : public MemorySymbol
	{
	public:
		FunctionSymbol(SymbolManager* manager, DataTypePtr type, const std::string& name, const std::string& comment = "")
			: MemorySymbol(manager, type, name, comment)
		{}

		Type getType() override {
			return FUNCTION;
		}

		int getSize() override {
			return 1;
		}
	};

	class GlobalVarSymbol : public MemorySymbol
	{
	public:
		GlobalVarSymbol(SymbolManager* manager, DataTypePtr type, const std::string& name, const std::string& comment = "")
			: MemorySymbol(manager, type, name, comment)
		{}

		Type getType() override {
			return GLOBAL_VAR;
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

	class LocalStackVarSymbol : public MemorySymbol
	{
	public:
		LocalStackVarSymbol(SymbolManager* manager, DataTypePtr type, const std::string& name, const std::string& comment = "")
			: MemorySymbol(manager, type, name, comment)
		{}

		Type getType() override {
			return LOCAL_STACK_VAR;
		}
	};
};