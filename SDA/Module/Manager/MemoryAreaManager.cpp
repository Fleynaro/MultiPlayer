#include "MemoryAreaManager.h"
#include <DB/Mappers/MemoryAreaMapper.h>

using namespace CE;
using namespace Symbol;

SymbolTableManager::SymbolTableManager(ProgramModule* module)
	: AbstractItemManager(module)
{
	m_memoryAreaMapper = new DB::SymbolTableMapper(this);
}

void SymbolTableManager::loadSymTables() {
	m_memoryAreaMapper->loadAll();

	//find the first global memory area and set it
	Iterator it(this);
	while (it.hasNext()) {
		auto memoryArea = it.next();
		if (memoryArea->getType() == SymbolTable::GLOBAL_SPACE) {
			m_globalSymbolTable = memoryArea;
			break;
		}
	}
}

void SymbolTableManager::createMainGlobalSymTable(int size) {
	m_globalSymbolTable = createSymbolTable(SymbolTable::GLOBAL_SPACE, size);
}

SymbolTable* SymbolTableManager::createSymbolTable(SymbolTable::SymbolTableType type, int size) {
	auto symbol = new SymbolTable(this, type, size);
	symbol->setMapper(m_memoryAreaMapper);
	symbol->setId(m_memoryAreaMapper->getNextId());
	getProgramModule()->getTransaction()->markAsNew(symbol);
	return symbol;
}

SymbolTable* SymbolTableManager::getSymbolTableById(DB::Id id) {
	return static_cast<SymbolTable*>(find(id));
}

Symbol::SymbolTable* SymbolTableManager::getMainGlobalSymTable() {
	return m_globalSymbolTable;
}

