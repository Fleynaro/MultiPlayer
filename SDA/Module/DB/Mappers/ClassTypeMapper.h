#pragma once
#include "DataTypeMapper.h"

namespace CE::DataType {
	class Class;
};

namespace DB
{
	class ClassTypeMapper : public ChildAbstractMapper
	{
	public:
		ClassTypeMapper(DataTypeMapper* parentMapper)
			: ChildAbstractMapper(parentMapper)
		{}

		void loadClasses(Database* db);

		IDomainObject* doLoad(Database* db, SQLite::Statement& query);
	protected:
		void loadInfoForClass(Database* db, CE::DataType::Class* Class);

		void loadMethodsForClass(Database* db, CE::DataType::Class* Class);

		void loadFieldsForClass(Database* db, CE::DataType::Class* Class);

		void saveClassFields(Database* db, CE::DataType::Class* Class);

		void saveClassMethods(Database* db, CE::DataType::Class* Class);

		void doInsert(Database* db, IDomainObject* obj) override;

		void doUpdate(Database* db, IDomainObject* obj) override;

		void doRemove(Database* db, IDomainObject* obj) override;

	private:
		void bind(SQLite::Statement& query, CE::DataType::Class& type);

		DataTypeMapper* getParentMapper();
	};
};