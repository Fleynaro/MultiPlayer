#pragma once
#include "DataTypeMapper.h"

namespace CE::DataType {
	class Structure;
};

namespace DB
{
	class StructureTypeMapper : public ChildAbstractMapper
	{
	public:
		StructureTypeMapper(DataTypeMapper* parentMapper);

		void loadStructures(Database* db);

		IDomainObject* doLoad(Database* db, SQLite::Statement& query);

		DataTypeMapper* getParentMapper();
	protected:
		void loadFieldsForStructure(Database* db, CE::DataType::Structure* structure);

		void saveFieldsForStructure(Database* db, CE::DataType::Structure* structure);

		void doInsert(Database* db, IDomainObject* obj) override;

		void doUpdate(Database* db, IDomainObject* obj) override;

		void doRemove(Database* db, IDomainObject* obj) override;

	private:
		void bind(SQLite::Statement& query, CE::DataType::Structure& structure);
	};
};