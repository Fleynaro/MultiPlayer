#pragma once
#include "MemorySymbol.h"

namespace CE::Function {
	class Function;
};

namespace CE::Symbol
{
	class FunctionSymbol : public AbstractSymbol
	{
	public:
		FunctionSymbol(SymbolManager* manager, DataTypePtr type, const std::string& name, const std::string& comment = "")
			: AbstractSymbol(manager, type, name, comment)
		{}

		Type getType() override {
			return FUNCTION;
		}

		int getSize() override {
			return 1;
		}

		Function::Function* getFunction() {
			return m_function;
		}

		void setFunction(Function::Function* function) {
			m_function = function;
		}

	private:
		Function::Function* m_function;
	};
};