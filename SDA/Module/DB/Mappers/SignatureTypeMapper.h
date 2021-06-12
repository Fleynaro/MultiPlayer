#pragma once
#include "DataTypeMapper.h"
#include <Code/Type/FunctionSignature.h>

namespace DB
{
	class SignatureTypeMapper : public ChildAbstractMapper
	{
	public:
		SignatureTypeMapper(DataTypeMapper* parentMapper);

		void loadStorages(Database* db);

		void loadParameterSymbols(Database* db);

		IDomainObject* doLoad(Database* db, SQLite::Statement& query) override;

	protected:

		void saveStorages(TransactionContext* ctx, CE::DataType::FunctionSignature& sig);

		void saveParameterSymbols(TransactionContext* ctx, CE::DataType::FunctionSignature& sig);

		void removeParameterSymbols(TransactionContext* ctx, CE::DataType::FunctionSignature& sig);

		void doInsert(TransactionContext* ctx, IDomainObject* obj) override;

		void doUpdate(TransactionContext* ctx, IDomainObject* obj) override;

		void doRemove(TransactionContext* ctx, IDomainObject* obj) override;

	private:
		void bind(SQLite::Statement& query, CE::DataType::FunctionSignature& type);

		DataTypeMapper* getParentMapper();
	};
};