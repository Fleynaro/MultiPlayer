#pragma once
#include "AbstractManager.h"
#include <Code/Symbol/Symbol.h>

namespace DB {
	class SymbolMapper;
};

namespace CE
{
	class SymbolManager : public AbstractItemManager
	{
	public:
		using Iterator = AbstractIterator<Symbol::AbstractSymbol>;
		
		SymbolManager(ProgramModule* module);

		void loadSymbols();

		void bind(Symbol::AbstractSymbol* symbol);

		Symbol::FuncParameterSymbol* getDefaultFuncParameterSymbol();

		Symbol::AbstractSymbol* getSymbolById(DB::Id id);

	private:
		Symbol::FuncParameterSymbol* m_defaultFuncParameterSymbol;
		DB::SymbolMapper* m_symbolMapper;
	};
};