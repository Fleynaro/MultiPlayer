#pragma once
#include "DataTypeMapper.h"
#include <Code/Type/Enum.h>

namespace DB
{
	class EnumTypeMapper : public ChildAbstractMapper
	{
	public:
		EnumTypeMapper(DataTypeMapper* parentMapper);

		IDomainObject* doLoad(Database* db, SQLite::Statement& query) override;
	protected:
		void saveEnumFields(TransactionContext* ctx, CE::DataType::Enum* Enum);

		void loadFieldsForEnum(Database* db, CE::DataType::Enum* Enum);


		void doInsert(TransactionContext* ctx, IDomainObject* obj) override;

		void doUpdate(TransactionContext* ctx, IDomainObject* obj) override;

		void doRemove(TransactionContext* ctx, IDomainObject* obj) override;

	private:
		void bind(SQLite::Statement& query, CE::DataType::Enum& type);

		DataTypeMapper* getParentMapper();
	};
};