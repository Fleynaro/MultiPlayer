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
	Statement query(db, "SELECT * FROM sda_func_decls");
	load(&db, query);
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

void commitType(Database* db, CE::DataTypePtr type) {
	if (!type->isCommited()) {
		type->getMapper()->insert(db, type->getType());
	}
}

void FunctionDeclMapper::saveFunctionDeclArguments(Database* db, CE::Function::FunctionDecl& decl) {
	{
		SQLite::Statement query(*db, "DELETE FROM sda_func_arguments WHERE decl_id=?1");
		query.bind(1, decl.getId());
		query.exec();
	}

	{
		int id = 0;
		for (auto type : decl.getSignature().getArgList()) {
			commitType(db, type);

			SQLite::Statement query(*db, "INSERT INTO sda_func_arguments (decl_id, id, name, type_id, pointer_lvl) \
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

void FunctionDeclMapper::doInsert(Database* db, IDomainObject* obj) {
	auto& decl = *static_cast<CE::Function::FunctionDecl*>(obj);
	commitType(db, decl.getSignature().getReturnType());

	SQLite::Statement query(*db, "INSERT INTO sda_func_decls (name, role, ret_type_id, ret_pointer_lvl, desc)\
				VALUES(?2, ?3, ?4, ?5, ?6)");
	bind(query, decl);
	query.exec();
	setNewId(db, obj);
	saveFunctionDeclArguments(db, decl);
}

void FunctionDeclMapper::doUpdate(Database* db, IDomainObject* obj) {
	auto& decl = *static_cast<CE::Function::FunctionDecl*>(obj);
	commitType(db, decl.getSignature().getReturnType());

	SQLite::Statement query(*db, "REPLACE INTO sda_func_decls (decl_id, name, role, ret_type_id, ret_pointer_lvl, desc)\
				VALUES(?1, ?2, ?3, ?4, ?5, ?6)");
	query.bind(1, obj->getId());
	bind(query, decl);
	query.exec();
	saveFunctionDeclArguments(db, decl);
}

void FunctionDeclMapper::doRemove(Database* db, IDomainObject* obj) {
	Statement query(*db, "DELETE FROM sda_func_decls WHERE decl_id=?1");
	query.bind(1, obj->getId());
	query.exec();
}

void FunctionDeclMapper::bind(SQLite::Statement& query, CE::Function::FunctionDecl& decl) {
	query.bind(2, decl.getName());
	query.bind(3, (int)decl.getRole());
	query.bind(4, decl.getSignature().getReturnType()->getId());
	query.bind(5, DataType::GetPointerLevelStr(decl.getSignature().getReturnType()));
	query.bind(6, decl.getDesc().getDesc());
}
