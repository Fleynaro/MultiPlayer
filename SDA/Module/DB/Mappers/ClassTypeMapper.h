#pragma once
#include "DataTypeMapper.h"
#include <Code/Type/Class.h>

namespace DB
{
	class ClassTypeMapper : public ChildAbstractMapper
	{
	public:
		ClassTypeMapper(DataTypeMapper* parentMapper)
			: ChildAbstractMapper(parentMapper)
		{}

		void loadClasses()
		{
			for (auto it : m_types) {
				if (it.second->getType()->getGroup() == DataType::Type::Group::Class) {
					auto Class = static_cast<DataType::Class*>(it.second->getType());
					loadInfoForClass(Class);
					loadMethodsForClass(Class);
					loadFieldsForClass(Class);
				}
			}
		}

		IDomainObject* doLoad(Database* db, SQLite::Statement& query);
	protected:
		void loadInfoForClass(Database* db, DataType::Class* Class);

		void loadMethodsForClass(Database* db, DataType::Class* Class);

		void loadFieldsForClass(Database* db, DataType::Class* Class);

		void saveClassFields(Database* db, DataType::Class* Class);

		void saveClassMethods(Database* db, DataType::Class* Class);

		void doInsert(Database* db, IDomainObject* obj) override;

		void doUpdate(Database* db, IDomainObject* obj) override;

		void doRemove(Database* db, IDomainObject* obj) override;

	private:
		void bind(SQLite::Statement& query, CE::DataType::Class& type);

		DataTypeMapper* getParentMapper();
	};
};