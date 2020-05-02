#include "FunctionDefMapper.h"
#include <Manager/FunctionDefManager.h>

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

CE::FunctionManager* FunctionDefMapper::getManager() {
	return static_cast<CE::FunctionManager*>(m_repository);
}

DomainObject* FunctionDefMapper::doLoad(Database* db, SQLite::Statement& query) {
	int def_id = query.getColumn("def_id");
	int def_offset = query.getColumn("offset");
	int decl_id = query.getColumn("decl_id");

	auto decl = getManager()->getFunctionDeclManager()->getFunctionDeclById(decl_id);
	if (decl == nullptr)
		return nullptr;

	auto definition =
		new Function::FunctionDefinition(
			getManager(),
			getManager()->getProgramModule()->toAbsAddr(def_offset),
			Function::AddressRangeList(),
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
		definition.addRange(Function::AddressRange(
			getManager()->getProgramModule()->toAbsAddr(query.getColumn("min_offset")),
			getManager()->getProgramModule()->toAbsAddr(query.getColumn("max_offset"))
		));
	}
}

void FunctionDefMapper::saveFunctionRanges(Database* db, CE::Function::FunctionDefinition& definition) {
	{
		SQLite::Statement query(*db, "DELETE FROM sda_func_ranges WHERE def_id=?1");
		query.bind(1, definition.getId());
		query.exec();
	}

	{
		int order_id = 0;
		for (auto& range : definition.getRangeList()) {
			SQLite::Statement query(*db, "INSERT INTO sda_func_ranges (def_id, order_id, min_offset, max_offset) \
					VALUES(?1, ?2, ?3, ?4)");
			query.bind(1, definition.getId());
			query.bind(2, order_id);
			query.bind(3, getManager()->getProgramModule()->toRelAddr(range.getMinAddress()));
			query.bind(4, getManager()->getProgramModule()->toRelAddr(range.getMaxAddress()));
			query.exec();
			order_id++;
		}
	}
}

void FunctionDefMapper::doInsert(Database* db, DomainObject* obj) {
	auto def = *(CE::Function::FunctionDefinition*)obj;

	SQLite::Statement query(*db, "INSERT INTO sda_func_defs (decl_id, offset)\
				VALUES(?2, ?3)");
	bind(query, def);
	query.exec();
}

void FunctionDefMapper::doUpdate(Database* db, DomainObject* obj) {
	auto def = *(CE::Function::FunctionDefinition*)obj;

	SQLite::Statement query(*db, "REPLACE INTO sda_func_defs (def_id, decl_id, offset)\
				VALUES(?1, ?2, ?3)");
	query.bind(1, def.getId());
	bind(query, def);
	query.exec();
}

void FunctionDefMapper::doRemove(Database* db, DomainObject* obj) {
	SQLite::Statement query(*db, "DELETE FROM sda_func_defs WHERE def_id=?1");
	query.bind(1, obj->getId());
	query.exec();
}

void FunctionDefMapper::bind(SQLite::Statement& query, CE::Function::FunctionDefinition& def) {
	query.bind(2, def.getDeclaration().getId());
	query.bind(3, getManager()->getProgramModule()->toRelAddr(def.getAddress()));
}
