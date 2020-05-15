#include "FunctionDefMapper.h"
#include <Manager/FunctionDefManager.h>
#include <Manager/ProcessModuleManager.h>

using namespace DB;
using namespace CE;

FunctionDefMapper::FunctionDefMapper(CE::FunctionManager* repository)
	: AbstractMapper(repository)
{}

void FunctionDefMapper::loadAll() {
	auto& db = getManager()->getProgramModule()->getDB();
	Statement query(db, "SELECT * FROM sda_func_defs");
	load(&db, query);
}

Id FunctionDefMapper::getNextId() {
	auto& db = getManager()->getProgramModule()->getDB();
	return GenerateNextId(&db, "sda_func_defs");
}

CE::FunctionManager* FunctionDefMapper::getManager() {
	return static_cast<CE::FunctionManager*>(m_repository);
}

IDomainObject* FunctionDefMapper::doLoad(Database* db, SQLite::Statement& query) {
	int def_id = query.getColumn("def_id");
	int decl_id = query.getColumn("decl_id");
	int module_id = query.getColumn("module_id");

	auto decl = getManager()->getFunctionDeclManager()->getFunctionDeclById(decl_id);
	if (decl == nullptr)
		return nullptr;

	auto module = getManager()->getProgramModule()->getProcessModuleManager()->getProcessModuleById(module_id);

	auto definition =
		new Function::FunctionDefinition(
			getManager(),
			module,
			AddressRangeList(),
			decl
		);

	
	definition->setId(def_id);
	loadFunctionRanges(db, *definition);
	return definition;
}

void FunctionDefMapper::loadFunctionRanges(Database* db, CE::Function::FunctionDefinition& definition) {
	SQLite::Statement query(*db, "SELECT * FROM sda_func_ranges WHERE def_id=?1 GROUP BY order_id");
	query.bind(1, definition.getId());

	while (query.executeStep())
	{
		definition.addRange(AddressRange(
			definition.getProcessModule()->toAbsAddr(query.getColumn("min_offset")),
			definition.getProcessModule()->toAbsAddr(query.getColumn("max_offset"))
		));
	}
}

void FunctionDefMapper::saveFunctionRanges(TransactionContext* ctx, CE::Function::FunctionDefinition& definition) {
	{
		SQLite::Statement query(*ctx->m_db, "DELETE FROM sda_func_ranges WHERE def_id=?1");
		query.bind(1, definition.getId());
		query.exec();
	}

	{
		int order_id = 0;
		for (auto& range : definition.getAddressRangeList()) {
			SQLite::Statement query(*ctx->m_db, "INSERT INTO sda_func_ranges (def_id, order_id, min_offset, max_offset) \
					VALUES(?1, ?2, ?3, ?4)");
			query.bind(1, definition.getId());
			query.bind(2, order_id);
			query.bind(3, definition.getProcessModule()->toRelAddr(range.getMinAddress()));
			query.bind(4, definition.getProcessModule()->toRelAddr(range.getMaxAddress()));
			query.exec();
			order_id++;
		}
	}
}

void FunctionDefMapper::doInsert(TransactionContext* ctx, IDomainObject* obj) {
	doUpdate(ctx, obj);
}

void FunctionDefMapper::doUpdate(TransactionContext* ctx, IDomainObject* obj) {
	auto& def = *static_cast<CE::Function::FunctionDefinition*>(obj);

	SQLite::Statement query(*ctx->m_db, "REPLACE INTO sda_func_defs (def_id, decl_id, module_id, save_id)\
				VALUES(?1, ?2, ?3, ?4)");
	query.bind(1, def.getId());
	bind(query, def);
	query.bind(4, ctx->m_saveId);
	query.exec();
	saveFunctionRanges(ctx, def);
}

void FunctionDefMapper::doRemove(TransactionContext* ctx, IDomainObject* obj) {
	SQLite::Statement query(*ctx->m_db, "DELETE FROM sda_func_defs WHERE def_id=?1");
	query.bind(1, obj->getId());
	query.exec();
}

void FunctionDefMapper::bind(SQLite::Statement& query, CE::Function::FunctionDefinition& def) {
	query.bind(2, def.getDeclaration().getId());
	query.bind(3, def.getProcessModule()->getId());
}
