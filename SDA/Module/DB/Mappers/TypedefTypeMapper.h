#pragma once
#include "DataTypeMapper.h"
#include <Code/Type/Typedef.h>

namespace DB
{
	class TypedefTypeMapper : public ChildAbstractMapper
	{
	public:
		TypedefTypeMapper(DataTypeMapper* parentMapper)
			: ChildAbstractMapper(parentMapper)
		{}

		void loadTypedefs(Database* db) {
			SQLite::Statement query(*db, "SELECT * FROM sda_typedefs");

			while (query.executeStep())
			{
				auto type = getTypeById(query.getColumn("type_id"));
				if (type != nullptr && type->getType()->getGroup() == DataType::Type::Group::Typedef) {
					auto Typedef = static_cast<DataType::Typedef*>(type->getType());
					auto refType = getType(query.getColumn("ref_type_id"), query.getColumn("pointer_lvl"), query.getColumn("array_size"));
					if (refType != nullptr)
						Typedef->setRefType(refType);
				}
			}
		}

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