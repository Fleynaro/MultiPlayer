#pragma once
#include "MemorySymbol.h"
#include "FuncParameterSymbol.h"
#include "FunctionSymbol.h"

namespace CE::Symbol
{
	static AbstractSymbol* CreateSymbol(SymbolManager* symbolManager, Type type, DataTypePtr dataType, const std::string& name, const std::string& comment) {
		AbstractSymbol* symbol = nullptr;
		switch (type)
		{
		case FUNCTION:
			symbol = new FunctionSymbol(symbolManager, dataType, name, comment);
			break;
		case GLOBAL_VAR:
			symbol = new GlobalVarSymbol(symbolManager, dataType, name, comment);
			break;
		case LOCAL_INSTR_VAR:
			symbol = new LocalInstrVarSymbol(symbolManager, dataType, name, comment);
			break;
		case LOCAL_STACK_VAR:
			symbol = new LocalStackVarSymbol(symbolManager, dataType, name, comment);
			break;
		case FUNC_PARAMETER:
			symbol = new FuncParameterSymbol(symbolManager, dataType, name, comment);
			break;
		}
		return symbol;
	}
};