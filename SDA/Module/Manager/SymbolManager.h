#pragma once
#include "AbstractManager.h"
#include <Code/Symbol/AbstractSymbol.h>

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

		Symbol::AbstractSymbol* createSymbol(Symbol::Type type, DataTypePtr dataType, const std::string& name, const std::string& comment = "");

		Symbol::AbstractSymbol* getSymbolById(DB::Id id);

	private:
		DB::SymbolMapper* m_symbolMapper;
	};
};