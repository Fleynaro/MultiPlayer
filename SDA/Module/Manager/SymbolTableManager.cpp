#include "SymbolTableManager.h"
#include <DB/Mappers/SymbolTableMapper.h>

using namespace CE;
using namespace Symbol;

SymbolTableManager::SymbolTableManager(Project* module)
	: AbstractItemManager(module)
{
	m_symbolTableMapper = new DB::SymbolTableMapper(this);
}

void SymbolTableManager::loadSymTables() {
	m_symbolTableMapper->loadAll();

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

SymbolTableManager::Factory CE::SymbolTableManager::getFactory(bool generateId) {
	return Factory(this, m_symbolTableMapper, generateId);
}

void SymbolTableManager::createMainGlobalSymTable(int size) {
	m_globalSymbolTable = getFactory().createSymbolTable(SymbolTable::GLOBAL_SPACE, size);
}

SymbolTable* SymbolTableManager::findSymbolTableById(DB::Id id) {
	return static_cast<SymbolTable*>(find(id));
}

Symbol::SymbolTable* SymbolTableManager::getMainGlobalSymTable() {
	return m_globalSymbolTable;
}

Symbol::SymbolTable* CE::SymbolTableManager::Factory::createSymbolTable(Symbol::SymbolTable::SymbolTableType type, int size) {
	auto symbol = new SymbolTable(m_symbolTableManager, type, size);
	symbol->setMapper(m_symbolTableMapper);
	if (m_generateId)
		symbol->setId(m_symbolTableMapper->getNextId());
	return symbol;
}
