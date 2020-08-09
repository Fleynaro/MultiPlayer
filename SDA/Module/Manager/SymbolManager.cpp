#include "SymbolManager.h"
#include <Code/Symbol/Symbol.h>
#include <DB/Mappers/SymbolMapper.h>

using namespace CE;
using namespace CE::Symbol;

SymbolManager::SymbolManager(ProgramModule* module)
	: AbstractItemManager(module)
{
	m_symbolMapper = new DB::SymbolMapper(this);
}

void SymbolManager::loadSymbols() {
	m_symbolMapper->loadAll();
}

AbstractSymbol* SymbolManager::createSymbol(Symbol::Type type, DataTypePtr dataType, const std::string& name, const std::string& comment) {
	auto symbol = CreateSymbol(this, type, dataType, name, comment);
	symbol->setMapper(m_symbolMapper);
	symbol->setId(m_symbolMapper->getNextId());
	getProgramModule()->getTransaction()->markAsNew(symbol);
	return symbol;
}

AbstractSymbol* CE::SymbolManager::getSymbolById(DB::Id id) {
	return static_cast<Symbol::AbstractSymbol*>(find(id));
}
