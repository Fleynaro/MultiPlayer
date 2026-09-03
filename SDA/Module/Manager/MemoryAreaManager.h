#pragma once
#include "AbstractManager.h"
#include <Code/Symbol/MemoryArea/MemoryArea.h>

namespace DB {
	class SymbolTableMapper;
};

namespace CE
{
	class SymbolTableManager : public AbstractItemManager
	{
	public:
		using Iterator = AbstractIterator<Symbol::SymbolTable>;

		SymbolTableManager(ProgramModule* module);

		void loadSymTables();

		void createMainGlobalSymTable(int size);

		Symbol::SymbolTable* createSymbolTable(Symbol::SymbolTable::SymbolTableType type, int size);

		Symbol::SymbolTable* getSymbolTableById(DB::Id id);

		Symbol::SymbolTable* getMainGlobalSymTable();

	private:
		Symbol::SymbolTable* m_globalSymbolTable = nullptr;
		DB::SymbolTableMapper* m_memoryAreaMapper;
	};
};