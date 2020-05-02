#pragma once
#include "DataTypeMapper.h"
#include <Code/Type/Enum.h>

namespace DB
{
	class EnumTypeMapper : public ChildAbstractMapper
	{
	public:
		EnumTypeMapper(DataTypeMapper* parentMapper)
			: ChildAbstractMapper(parentMapper)
		{}

		DomainObject* doLoad(Database* db, SQLite::Statement& query) override;
	protected:
		void saveEnumFields(Database* db, DataType::Enum* Enum);

		void loadFieldsForEnum(Database* db, DataType::Enum* Enum);


		void doInsert(Database* db, DomainObject* obj) override;

		void doUpdate(Database* db, DomainObject* obj) override;

		void doRemove(Database* db, DomainObject* obj) override;

	private:
		void bind(SQLite::Statement& query, CE::DataType::Enum& type);

		DataTypeMapper* getParentMapper();
	};
};