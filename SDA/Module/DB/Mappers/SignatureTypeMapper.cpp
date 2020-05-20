#include "SignatureTypeMapper.h"
#include <GhidraSync/Mappers/GhidraSignatureTypeMapper.h>
#include <Manager/TypeManager.h>

using namespace DB;
using namespace CE;

SignatureTypeMapper::SignatureTypeMapper(DataTypeMapper* parentMapper)
	: ChildAbstractMapper(parentMapper)
{}

IDomainObject* SignatureTypeMapper::doLoad(Database* db, SQLite::Statement& query) {
	auto type = new DataType::Signature(
		getParentMapper()->getManager(),
		query.getColumn("name"),
		query.getColumn("desc")
	);
	type->setId(query.getColumn("id"));
	type->setGhidraMapper(getParentMapper()->getManager()->m_ghidraDataTypeMapper->m_signatureTypeMapper);
	loadFunctionDeclArguments(db, *type);
	return type;
}

void SignatureTypeMapper::loadFunctionDeclArguments(Database* db, DataType::Signature& sig) {
	Statement query(*db, "SELECT * FROM sda_signature_args WHERE signature_id=?1 GROUP BY id");
	query.bind(1, sig.getId());

	while (query.executeStep())
	{
		auto type = getParentMapper()->getManager()->getProgramModule()->getTypeManager()->getTypeById(query.getColumn("type_id"));
		if (type == nullptr) {
			type = getParentMapper()->getManager()->getProgramModule()->getTypeManager()->getDefaultType();
		}

		sig.addArgument(query.getColumn("name"), DataType::GetUnit(type, query.getColumn("pointer_lvl")));
	}
}

void SignatureTypeMapper::saveFunctionDeclArguments(TransactionContext* ctx, DataType::Signature& sig) {
	removeFunctionDeclArguments(ctx, sig);

	{
		int id = 0;
		for (auto arg : sig.getArguments()) {
			SQLite::Statement query(*ctx->m_db, "INSERT INTO sda_signature_args (signature_id, id, name, type_id, pointer_lvl) \
					VALUES(?1, ?2, ?3, ?4, ?5)");
			query.bind(1, sig.getId());
			query.bind(2, id);
			query.bind(3, arg.first);
			query.bind(4, arg.second->getId());
			query.bind(5, DataType::GetPointerLevelStr(arg.second));
			query.exec();
			id++;
		}
	}
}

void SignatureTypeMapper::removeFunctionDeclArguments(TransactionContext* ctx, CE::DataType::Signature& sig) {
	SQLite::Statement query(*ctx->m_db, "DELETE FROM sda_signature_args WHERE signature_id=?1");
	query.bind(1, sig.getId());
	query.exec();
}

void SignatureTypeMapper::doInsert(TransactionContext* ctx, IDomainObject* obj) {
	doUpdate(ctx, obj);
}

void SignatureTypeMapper::doUpdate(TransactionContext* ctx, IDomainObject* obj) {
	auto signature = static_cast<DataType::Signature*>(obj);
	SQLite::Statement query(*ctx->m_db, "REPLACE INTO sda_signatures (signature_id, ret_type_id, ret_pointer_lvl) VALUES(?1, ?2, ?3)");
	query.bind(1, signature->getId());
	bind(query, *signature);
	query.exec();
	saveFunctionDeclArguments(ctx, *signature);
}

void SignatureTypeMapper::doRemove(TransactionContext* ctx, IDomainObject* obj) {
	if (ctx->m_notDelete)
		return;
	SQLite::Statement query(*ctx->m_db, "DELETE FROM sda_signatures WHERE signature_id=?1");
	query.bind(1, obj->getId());
	query.exec();

	auto signature = static_cast<DataType::Signature*>(obj);
	removeFunctionDeclArguments(ctx, *signature);
}

void SignatureTypeMapper::bind(SQLite::Statement& query, DataType::Signature& sig) {
	query.bind(2, sig.getReturnType()->getId());
	query.bind(3, DataType::GetPointerLevelStr(sig.getReturnType()));
}

DataTypeMapper* SignatureTypeMapper::getParentMapper() {
	return static_cast<DataTypeMapper*>(m_parentMapper);
}
