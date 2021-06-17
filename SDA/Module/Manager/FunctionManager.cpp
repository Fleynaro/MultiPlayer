#include "FunctionManager.h"
#include "TypeManager.h"
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

