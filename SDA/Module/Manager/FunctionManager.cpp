#include "FunctionManager.h"
#include "MemoryAreaManager.h"
#include "TypeManager.h"
#include "SymbolManager.h"
#include <DB/Mappers/FunctionMapper.h>
#include <GhidraSync/Mappers/GhidraFunctionMapper.h>

using namespace CE;

FunctionManager::FunctionManager(Project* module)
	: AbstractItemManager(module)
{
	m_funcMapper = new DB::FunctionMapper(this);
	m_ghidraFunctionMapper = new Ghidra::FunctionMapper(this, getProject()->getTypeManager()->m_ghidraDataTypeMapper);
}

FunctionManager::~FunctionManager() {
	delete m_ghidraFunctionMapper;
}

FunctionManager::Factory FunctionManager::getFactory(bool generateId) {
	return Factory(this, m_ghidraFunctionMapper, m_funcMapper, generateId);
}

void FunctionManager::loadFunctions() {
	m_funcMapper->loadAll();
}

void FunctionManager::loadFunctionsFrom(ghidra::packet::SDataFullSyncPacket* dataPacket) {
	m_ghidraFunctionMapper->load(dataPacket);
}

Function::Function* CE::FunctionManager::findFunctionById(DB::Id id) {
	return dynamic_cast<Function::Function*>(find(id));
}

Function::Function* CE::FunctionManager::findFunctionByGhidraId(Ghidra::Id id)
{
	Iterator it(this);
	while (it.hasNext()) {
		auto function = it.next();
		if (function->getGhidraId() == id) {
			return function;
		}
	}
	return nullptr;
}

Function::Function* CE::FunctionManager::Factory::createFunction(Symbol::FunctionSymbol* functionSymbol, Decompiler::FunctionPCodeGraph* funcGraph, bool generateId) {
	auto func = new Function::Function(m_functionManager, functionSymbol, funcGraph);
	func->setMapper(m_funcMapper);
	func->setGhidraMapper(m_ghidraFunctionMapper);
	if (generateId)
		func->setId(m_funcMapper->getNextId());
	return func;
}

