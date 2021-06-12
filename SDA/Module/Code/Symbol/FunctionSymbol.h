#pragma once
#include "MemorySymbol.h"

namespace CE::Function {
	class Function;
};

namespace CE::Symbol
{
	class FunctionSymbol : public GlobalVarSymbol
	{
	public:
		FunctionSymbol(SymbolManager* manager, int64_t offset, DataTypePtr type, const std::string& name, const std::string& comment = "")
			: GlobalVarSymbol(manager, offset, type, name, comment)
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

		DataType::IFunctionSignature* getSignature() {
			return dynamic_cast<DataType::IFunctionSignature*>(getDataType()->getType());
		}

		void setFunction(Function::Function* function) {
			m_function = function;
		}

	private:
		Function::Function* m_function;
	};
};