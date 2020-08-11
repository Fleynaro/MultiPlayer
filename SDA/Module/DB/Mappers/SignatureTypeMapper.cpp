#include "SignatureTypeMapper.h"
#include <GhidraSync/Mappers/GhidraSignatureTypeMapper.h>
#include <Manager/TypeManager.h>
#include <Manager/SymbolManager.h>

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
	return type;
}

void SignatureTypeMapper::loadStorages(Database* db) {
	Statement query(*db, "SELECT * FROM sda_signature_storages");
	
	while (query.executeStep())
	{
		int signature_id = query.getColumn("signature_id");
		auto signature = dynamic_cast<DataType::Signature*>(getParentMapper()->getManager()->getTypeById(signature_id));
		if (!signature)
			continue;

		int index = query.getColumn("idx");
		auto storage_type = (DataType::Storage::StorageType)(int)query.getColumn("storage_type");
		int register_id = query.getColumn("register_id");
		int offset = query.getColumn("offset");

		auto storage = new DataType::Storage(index, storage_type, register_id, offset);
		signature->getCustomStorages().push_back(storage);
	}
}

void SignatureTypeMapper::saveStorages(TransactionContext* ctx, DataType::Signature& sig) {
	{
		SQLite::Statement query(*ctx->m_db, "DELETE FROM sda_signature_storages WHERE signature_id=?1");
		query.bind(1, sig.getId());
		query.exec();
	}

	{
		for (auto storage : sig.getCustomStorages()) {
			SQLite::Statement query(*ctx->m_db, "INSERT INTO sda_signature_storages (signature_id, idx, storage_type, register_id, offset) \
					VALUES(?1, ?2, ?3, ?4, ?5)");
			query.bind(1, sig.getId());
			query.bind(2, storage->getIndex());
			query.bind(3, storage->getType());
			query.bind(4, storage->getRegisterId());
			query.bind(5, storage->getOffset());
			query.exec();
		}
	}
}

void SignatureTypeMapper::loadParameterSymbols(Database* db) {
	Statement query(*db, "SELECT * FROM sda_signature_params ORDER BY signature_id, order_id");
	
	while (query.executeStep())
	{
		int signature_id = query.getColumn("signature_id");
		int param_symbol_id = query.getColumn("param_symbol_id");
		auto signature = dynamic_cast<DataType::Signature*>(getParentMapper()->getManager()->getTypeById(signature_id));
		if (!signature)
			continue;
		auto param_symbol = dynamic_cast<Symbol::FuncParameterSymbol*>(getParentMapper()->getManager()->getProgramModule()->getSymbolManager()->getSymbolById(param_symbol_id));
		if (!param_symbol) {
			param_symbol = getParentMapper()->getManager()->getProgramModule()->getSymbolManager()->getDefaultFuncParameterSymbol();
		}
		signature->addParameter(param_symbol);
	}
}

void SignatureTypeMapper::saveParameterSymbols(TransactionContext* ctx, DataType::Signature& sig) {
	removeParameterSymbols(ctx, sig);

	{
		int id = 0;
		for (auto param : sig.getParameters()) {
			SQLite::Statement query(*ctx->m_db, "INSERT INTO sda_signature_params (signature_id, order_id, param_symbol_id) \
					VALUES(?1, ?2, ?3)");
			query.bind(1, sig.getId());
			query.bind(2, id);
			query.bind(3, param->getId());
			query.exec();
			id++;
		}
	}
}

void SignatureTypeMapper::removeParameterSymbols(TransactionContext* ctx, CE::DataType::Signature& sig) {
	SQLite::Statement query(*ctx->m_db, "DELETE FROM sda_signature_params WHERE signature_id=?1");
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
	saveParameterSymbols(ctx, *signature);
	saveStorages(ctx, *signature);
}

void SignatureTypeMapper::doRemove(TransactionContext* ctx, IDomainObject* obj) {
	if (ctx->m_notDelete)
		return;
	SQLite::Statement query(*ctx->m_db, "DELETE FROM sda_signatures WHERE signature_id=?1");
	query.bind(1, obj->getId());
	query.exec();

	auto signature = static_cast<DataType::Signature*>(obj);
	removeParameterSymbols(ctx, *signature);
}

void SignatureTypeMapper::bind(SQLite::Statement& query, DataType::Signature& sig) {
	query.bind(2, sig.getReturnType()->getId());
	query.bind(3, DataType::GetPointerLevelStr(sig.getReturnType()));
}

DataTypeMapper* SignatureTypeMapper::getParentMapper() {
	return static_cast<DataTypeMapper*>(m_parentMapper);
}
