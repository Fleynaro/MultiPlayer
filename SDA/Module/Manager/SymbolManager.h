#pragma once
#include "AbstractManager.h"
#include <Code/Symbol/AbstractSymbol.h>

namespace DB {
	class SymbolMapper;
};

namespace CE
{
	class GlobalVarManager : public AbstractItemManager
	{
	public:
		using Iterator = AbstractIterator<Symbol::AbstractSymbol>;
		
		GlobalVarManager(ProgramModule* module);

		void loadSymbols();

		//Symbol::AbstractSymbol* createSymbol(DataTypePtr type, const std::string& name, const std::string& comment = "");

		Symbol::AbstractSymbol* getSymbolById(DB::Id id) {
			return static_cast<Symbol::AbstractSymbol*>(find(id));
		}

	private:
		DB::SymbolMapper* m_symbolMapper;
	};
};