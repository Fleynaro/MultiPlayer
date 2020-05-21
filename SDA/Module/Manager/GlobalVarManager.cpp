#include "GlobalVarManager.h"
#include <DB/Mappers/GlobalVarMapper.h>
#include <GhidraSync/Mappers/GhidraGlobalVarMapper.h>
#include <Manager/TypeManager.h>

using namespace CE;
using namespace CE::Variable;

GlobalVarManager::GlobalVarManager(ProgramModule* module)
	: AbstractItemManager(module)
{
	m_globalVarMapper = new DB::GlobalVarMapper(this);
	m_ghidraGlobalVarMapper = new Ghidra::GlobalVarMapper(this, getProgramModule()->getTypeManager()->m_ghidraDataTypeMapper);
}

void GlobalVarManager::loadGlobalVars() {
	m_globalVarMapper->loadAll();
}

void GlobalVarManager::loadGlobalVarsFrom(ghidra::packet::SDataFullSyncPacket* dataPacket) {
	m_ghidraGlobalVarMapper->load(dataPacket);
}

GlobalVar* GlobalVarManager::createGlobalVar(ProcessModule* module, void* addr, const std::string& name, const std::string& comment) {
	auto gvar = new GlobalVar(this, module, addr, name, comment);
	gvar->setMapper(m_globalVarMapper);
	gvar->setGhidraMapper(m_ghidraGlobalVarMapper);
	gvar->setId(m_globalVarMapper->getNextId());
	getProgramModule()->getTransaction()->markAsNew(gvar);
	return gvar;
}

GlobalVar* GlobalVarManager::getGlobalVarById(DB::Id id) {
	return static_cast<GlobalVar*>(find(id));
}
