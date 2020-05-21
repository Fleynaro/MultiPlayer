#include "GlobalVarMapper.h"
#include <Manager/GlobalVarManager.h>
#include <Manager/ProcessModuleManager.h>
#include <Manager/TypeManager.h>
#include <GhidraSync/Mappers/GhidraGlobalVarMapper.h>

using namespace DB;
using namespace CE;
using namespace CE::Variable;

GlobalVarMapper::GlobalVarMapper(IRepository* repository)
	: AbstractMapper(repository)
{}

void GlobalVarMapper::loadAll() {
	auto& db = getManager()->getProgramModule()->getDB();
	Statement query(db, "SELECT * FROM sda_gvars");
	load(&db, query);
}

Id GlobalVarMapper::getNextId() {
	auto& db = getManager()->getProgramModule()->getDB();
	return GenerateNextId(&db, "sda_gvars");
}

GlobalVarManager* GlobalVarMapper::getManager() {
	return static_cast<GlobalVarManager*>(m_repository);
}

IDomainObject* GlobalVarMapper::doLoad(Database* db, SQLite::Statement& query) {
	auto module = getManager()->getProgramModule()->getProcessModuleManager()->getProcessModuleById(query.getColumn("module_id"));
	if (module == nullptr)
		return nullptr;

	auto type = getManager()->getProgramModule()->getTypeManager()->getTypeById(query.getColumn("type_id"));
	if (type == nullptr) {
		type = getManager()->getProgramModule()->getTypeManager()->getDefaultType();
	}

	std::string name = query.getColumn("name");
	std::string comment = query.getColumn("desc");
	auto gVar = new GlobalVar(
		getManager(),
		module,
		module->toAbsAddr(query.getColumn("offset")),
		name,
		comment
	);

	gVar->setType(DataType::GetUnit(type, query.getColumn("pointer_lvl")));
	gVar->setId(query.getColumn("id"));
	gVar->setGhidraMapper(getManager()->m_ghidraGlobalVarMapper);
	return gVar;
}

void GlobalVarMapper::doInsert(TransactionContext* ctx, IDomainObject* obj) {
	doUpdate(ctx, obj);
}

void GlobalVarMapper::doUpdate(TransactionContext* ctx, IDomainObject* obj) {
	auto gvar = static_cast<GlobalVar*>(obj);

	SQLite::Statement query(*ctx->m_db, "REPLACE INTO sda_gvars (id, name, module_id, offset, type_id, pointer_lvl, desc, save_id)\
				VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)");
	query.bind(1, gvar->getId());
	bind(query, *gvar);
	query.bind(8, ctx->m_saveId);
	query.exec();
}

void GlobalVarMapper::doRemove(TransactionContext* ctx, IDomainObject* obj) {
	std::string action_query_text =
		ctx->m_notDelete ? "UPDATE sda_gvars SET deleted=1" : "DELETE FROM sda_gvars";
	Statement query(*ctx->m_db, action_query_text + " WHERE id=?1");
	query.bind(1, obj->getId());
	query.exec();
}

void GlobalVarMapper::bind(SQLite::Statement& query, CE::Variable::GlobalVar& gvar) {
	query.bind(2, gvar.getName());
	query.bind(3, gvar.getProcessModule()->getId());
	query.bind(4, gvar.getProcessModule()->toRelAddr(gvar.getAddress()));
	query.bind(5, gvar.getType()->getId());
	query.bind(6, DataType::GetPointerLevelStr(gvar.getType()));
	query.bind(7, gvar.getComment());
}
