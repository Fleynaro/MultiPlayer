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
	Id sig_id = query.getColumn("signature_id");
	std::string decl_name = query.getColumn("name");
	std::string decl_desc = query.getColumn("desc");
	DataType::Signature* signature = nullptr;

	auto type = getManager()->getProgramModule()->getTypeManager()->getTypeById(sig_id);
	if (!(signature = dynamic_cast<DataType::Signature*>(type)))
		return nullptr;
	

	if (Function::FunctionDecl::isFunction(decl_role)) {
		decl = new Function::FunctionDecl(
			getManager(),
			signature,
			decl_name,
			decl_desc
		);
	}
	else {
		decl = new Function::MethodDecl(
			getManager(),
			signature,
			decl_name,
			decl_desc
		);
		static_cast<Function::MethodDecl*>(decl)->setRole((Function::MethodDecl::Role)(int)query.getColumn("role"));
	}
	decl->setId(decl_id);
	decl->setExported((bool)(int)query.getColumn("exported"));
	return decl;
}



void FunctionDeclMapper::doInsert(TransactionContext* ctx, IDomainObject* obj) {
	doUpdate(ctx, obj);
}

void FunctionDeclMapper::doUpdate(TransactionContext* ctx, IDomainObject* obj) {
	auto& decl = *static_cast<CE::Function::FunctionDecl*>(obj);

	SQLite::Statement query(*ctx->m_db, "REPLACE INTO sda_func_decls (decl_id, name, role, signature_id, exported, desc, save_id)\
				VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)");
	query.bind(1, obj->getId());
	bind(query, decl);
	query.bind(7, ctx->m_saveId);
	query.exec();
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
	query.bind(4, decl.getSignature()->getId());
	query.bind(5, (int)decl.isExported());
	query.bind(6, decl.getComment());
}
