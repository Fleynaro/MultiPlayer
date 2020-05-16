#include "FunctionDeclMapper.h"
#include <Manager/FunctionDeclManager.h>
#include <Manager/TypeManager.h>

using namespace DB;
using namespace CE;

FunctionDeclMapper::FunctionDeclMapper(IRepository* repository)
	: AbstractMapper(repository)
{}

void FunctionDeclMapper::loadAll() {
	auto& db = getManager()->getProgramModule()->getDB();
	Statement query(db, "SELECT * FROM sda_func_decls WHERE deleted=0");
	load(&db, query);
}

Id FunctionDeclMapper::getNextId() {
	auto& db = getManager()->getProgramModule()->getDB();
	return GenerateNextId(&db, "sda_func_decls");
}

CE::FunctionDeclManager* FunctionDeclMapper::getManager() {
	return static_cast<CE::FunctionDeclManager*>(m_repository);
}

IDomainObject* FunctionDeclMapper::doLoad(Database* db, SQLite::Statement& query) {
	Function::FunctionDecl* decl;
	auto decl_role = (Function::FunctionDecl::Role)(int)query.getColumn("role");
	Id decl_id = query.getColumn("decl_id");
	std::string decl_name = query.getColumn("name");
	std::string decl_desc = query.getColumn("desc");

	if (Function::FunctionDecl::isFunction(decl_role)) {
		decl = new Function::FunctionDecl(
			getManager(),
			decl_name,
			decl_desc
		);
	}
	else {
		decl = new Function::MethodDecl(
			getManager(),
			decl_name,
			decl_desc
		);
		static_cast<Function::MethodDecl*>(decl)->setRole((Function::MethodDecl::Role)(int)query.getColumn("role"));
	}
	decl->setId(decl_id);
	decl->setExported((bool)(int)query.getColumn("exported"));

	auto type = getManager()->getProgramModule()->getTypeManager()->getTypeById(query.getColumn("ret_type_id"));
	if (type == nullptr) {
		type = getManager()->getProgramModule()->getTypeManager()->getDefaultReturnType();
	}

	decl->getSignature().setReturnType(
		DataType::GetUnit(type, query.getColumn("ret_pointer_lvl")));
	loadFunctionDeclArguments(db, *decl);
	return decl;
}

void FunctionDeclMapper::loadFunctionDeclArguments(Database* db, CE::Function::FunctionDecl& decl) {
	Statement query(*db, "SELECT * FROM sda_func_arguments WHERE decl_id=?1 GROUP BY id");
	query.bind(1, decl.getId());

	while (query.executeStep())
	{
		auto type = getManager()->getProgramModule()->getTypeManager()->getTypeById(query.getColumn("type_id"));
		if (type == nullptr) {
			type = getManager()->getProgramModule()->getTypeManager()->getDefaultType();
		}

		decl.addArgument(DataType::GetUnit(type, query.getColumn("pointer_lvl")), query.getColumn("name"));
	}
}

void FunctionDeclMapper::saveFunctionDeclArguments(TransactionContext* ctx, CE::Function::FunctionDecl& decl) {
	{
		SQLite::Statement query(*ctx->m_db, "DELETE FROM sda_func_arguments WHERE decl_id=?1");
		query.bind(1, decl.getId());
		query.exec();
	}

	{
		int id = 0;
		for (auto type : decl.getSignature().getArgList()) {
			SQLite::Statement query(*ctx->m_db, "INSERT INTO sda_func_arguments (decl_id, id, name, type_id, pointer_lvl) \
					VALUES(?1, ?2, ?3, ?4, ?5)");
			query.bind(1, decl.getId());
			query.bind(2, id);
			query.bind(3, decl.getArgNameList()[id]);
			query.bind(4, type->getId());
			query.bind(5, DataType::GetPointerLevelStr(type));
			query.exec();
			id++;
		}
	}
}

void FunctionDeclMapper::doInsert(TransactionContext* ctx, IDomainObject* obj) {
	doUpdate(ctx, obj);
}

void FunctionDeclMapper::doUpdate(TransactionContext* ctx, IDomainObject* obj) {
	auto& decl = *static_cast<CE::Function::FunctionDecl*>(obj);

	SQLite::Statement query(*ctx->m_db, "REPLACE INTO sda_func_decls (decl_id, name, role, exported, ret_type_id, ret_pointer_lvl, desc, save_id)\
				VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)");
	query.bind(1, obj->getId());
	bind(query, decl);
	query.bind(8, ctx->m_saveId);
	query.exec();
	saveFunctionDeclArguments(ctx, decl);
}

void FunctionDeclMapper::doRemove(TransactionContext* ctx, IDomainObject* obj) {
	std::string action_query_text =
		ctx->m_notDelete ? "UPDATE sda_func_decls SET deleted=1" : "DELETE FROM sda_func_decls";
	Statement query(*ctx->m_db, action_query_text + " WHERE decl_id=?1");
	query.bind(1, obj->getId());
	query.exec();
}

void FunctionDeclMapper::bind(SQLite::Statement& query, CE::Function::FunctionDecl& decl) {
	query.bind(2, decl.getName());
	query.bind(3, (int)decl.getRole());
	query.bind(4, (int)decl.isExported());
	query.bind(5, decl.getSignature().getReturnType()->getId());
	query.bind(6, DataType::GetPointerLevelStr(decl.getSignature().getReturnType()));
	query.bind(7, decl.getComment());
}
