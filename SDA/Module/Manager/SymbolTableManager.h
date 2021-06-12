#pragma once
#include "AbstractManager.h"
#include <Code/Symbol/SymbolTable/SymbolTable.h>

namespace DB {
	class SymbolTableMapper;
};

namespace CE
{
	class SymbolTableManager : public AbstractItemManager
	{
	public:
		class Factory : public AbstractFactory
		{
			SymbolTableManager* m_symbolTableManager;
			DB::SymbolTableMapper* m_symbolTableMapper;
		public:
			Factory(SymbolTableManager* symbolTableManager, DB::SymbolTableMapper* symbolTableMapper, bool generateId)
				: m_symbolTableManager(symbolTableManager), m_symbolTableMapper(symbolTableMapper), AbstractFactory(generateId)
			{}

			Symbol::SymbolTable* createSymbolTable(Symbol::SymbolTable::SymbolTableType type, int size);
		};

		using Iterator = AbstractIterator<Symbol::SymbolTable>;

		SymbolTableManager(Project* module);

		void loadSymTables();

		Factory getFactory(bool generateId = true);

		void createMainGlobalSymTable(int size);

		Symbol::SymbolTable* findSymbolTableById(DB::Id id);

		Symbol::SymbolTable* getMainGlobalSymTable();

	private:
		Symbol::SymbolTable* m_globalSymbolTable = nullptr;
		DB::SymbolTableMapper* m_symbolTableMapper;
	};
};