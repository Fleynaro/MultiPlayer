#pragma once
#include "StructureTypeMapper.h"

namespace CE::DataType {
	class Class;
};

namespace DB
{
	class ClassTypeMapper : public ChildAbstractMapper
	{
	public:
		ClassTypeMapper(StructureTypeMapper* parentMapper);

		void loadClasses(Database* db);

		IDomainObject* doLoad(Database* db, SQLite::Statement& query);
	protected:
		void loadMethodsForClass(Database* db, CE::DataType::Class* Class);

		void saveMethodsForClass(TransactionContext* ctx, CE::DataType::Class* Class);

		void doInsert(TransactionContext* ctx, IDomainObject* obj) override;

		void doUpdate(TransactionContext* ctx, IDomainObject* obj) override;

		void doRemove(TransactionContext* ctx, IDomainObject* obj) override;

	private:
		void bind(SQLite::Statement& query, CE::DataType::Class& type);

		DataTypeMapper* getParentMapper();
	};
};