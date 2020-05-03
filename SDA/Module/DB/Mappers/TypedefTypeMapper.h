#pragma once
#include "DataTypeMapper.h"
#include <Code/Type/Typedef.h>

namespace DB
{
	class TypedefTypeMapper : public ChildAbstractMapper
	{
	public:
		TypedefTypeMapper(DataTypeMapper* parentMapper);

		void loadTypedefs(Database* db);

		IDomainObject* doLoad(Database* db, SQLite::Statement& query) override;
	protected:
		void doInsert(Database* db, IDomainObject* obj) override;

		void doUpdate(Database* db, IDomainObject* obj) override;

		void doRemove(Database* db, IDomainObject* obj) override;

	private:
		void bind(SQLite::Statement& query, CE::DataType::Typedef& type);

		DataTypeMapper* getParentMapper();
	};
};