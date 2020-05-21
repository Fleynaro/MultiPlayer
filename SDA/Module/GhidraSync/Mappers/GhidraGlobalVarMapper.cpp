#include "GhidraGlobalVarMapper.h"
#include "GhidraDataTypeMapper.h"
#include <Manager/GlobalVarManager.h>
#include <Manager/TypeManager.h>
#include <Manager/ProcessModuleManager.h>

using namespace CE;
using namespace CE::Ghidra;

GlobalVarMapper::GlobalVarMapper(CE::GlobalVarManager* globalVarManager, DataTypeMapper* dataTypeMapper)
	: m_globalVarManager(globalVarManager), m_dataTypeMapper(dataTypeMapper)
{}

void GlobalVarMapper::load(packet::SDataFullSyncPacket* dataPacket) {
	for (auto gvarDesc : dataPacket->globalVars) {
		auto gvar = m_globalVarManager->getGlobalVarById(gvarDesc.id);
		if (gvar == nullptr) {
			auto mainModule = m_globalVarManager->getProgramModule()->getProcessModuleManager()->getMainModule();
			gvar = m_globalVarManager->createGlobalVar(mainModule, mainModule->toAbsAddr((int)gvarDesc.id), gvarDesc.name, gvarDesc.comment);
		}
		changeGvarByDesc(gvar, gvarDesc);
	}
}

void markObjectAsSynced(SyncContext* ctx, Variable::GlobalVar* gvar) {
	SQLite::Statement query(*ctx->m_db, "UPDATE sda_gvars SET ghidra_sync_id=?1 WHERE id=?2");
	query.bind(1, ctx->m_syncId);
	query.bind(2, gvar->getId());
	query.exec();
}

void GlobalVarMapper::upsert(SyncContext* ctx, IObject* obj) {
	auto gvar = static_cast<Variable::GlobalVar*>(obj);
	ctx->m_dataPacket->globalVars.push_back(buildDesc(gvar));
	markObjectAsSynced(ctx, gvar);
}

void GlobalVarMapper::remove(SyncContext* ctx, IObject* obj) {
	auto gvar = static_cast<Variable::GlobalVar*>(obj);
	ctx->m_dataPacket->removed_globalVars.push_back(gvar->getGhidraId());
	markObjectAsSynced(ctx, gvar);
}

void GlobalVarMapper::changeGvarByDesc(Variable::GlobalVar* gvar, const variable::SGlobalVar& gvarDesc) {
	gvar->setName(gvarDesc.name);
	gvar->setComment(gvarDesc.comment);
	gvar->setType(m_dataTypeMapper->getTypeByDesc(gvarDesc.type));
}

variable::SGlobalVar GlobalVarMapper::buildDesc(Variable::GlobalVar* gvar) {
	variable::SGlobalVar gvarDesc;
	gvarDesc.__set_id(gvar->getGhidraId());
	gvarDesc.__set_name(gvar->getName());
	gvarDesc.__set_comment(gvar->getComment());
	gvarDesc.__set_type(m_dataTypeMapper->buildTypeUnitDesc(gvar->getType()));
	return gvarDesc;
}
