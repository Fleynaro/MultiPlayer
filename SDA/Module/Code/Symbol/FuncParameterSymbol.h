#pragma once
#include "AbstractSymbol.h"

namespace CE::Symbol
{
	class FuncParameterSymbol : public AbstractSymbol
	{
	public:
		FuncParameterSymbol(SymbolManager* manager, DataTypePtr type, const std::string& name, const std::string& comment = "")
			: AbstractSymbol(manager, type, name, comment)
		{}

		Type getType() override {
			return FUNC_PARAMETER;
		}
	};
};