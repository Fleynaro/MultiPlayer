#include "SymbolManager.h"
#include <DB/Mappers/SymbolMapper.h>
#include <Manager/TypeManager.h>

using namespace CE;
using namespace CE::Symbol;

SymbolManager::SymbolManager(ProgramModule* module)
	: AbstractItemManager(module)
{
	m_symbolMapper = new DB::SymbolMapper(this);
	m_defaultFuncParameterSymbol = new Symbol::FuncParameterSymbol(this, DataType::GetUnit(module->getTypeManager()->getDefaultType()), "unknown");
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

Symbol::FuncParameterSymbol* SymbolManager::getDefaultFuncParameterSymbol() {
	return m_defaultFuncParameterSymbol;
}

AbstractSymbol* CE::SymbolManager::getSymbolById(DB::Id id) {
	return static_cast<Symbol::AbstractSymbol*>(find(id));
}
