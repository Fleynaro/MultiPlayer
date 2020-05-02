#pragma once
#include <DB/AbstractMapper.h>
#include <Code/Type/AbstractType.h>

namespace CE {
	class TypeManager;
};

namespace DB
{
	class EnumTypeMapper;
	class ClassTypeMapper;
	class TypedefTypeMapper;

	class DataTypeMapper : public AbstractMapper
	{
	public:
		EnumTypeMapper* m_enumTypeMapper;
		ClassTypeMapper* m_classTypeMapper;
		TypedefTypeMapper* m_typedefTypeMapper;

		DataTypeMapper(IRepository* repository);

		void loadAll() {

		}

		CE::TypeManager* getManager();
	protected:
		DomainObject* doLoad(Database* db, SQLite::Statement& query) override;

		void doInsert(Database* db, DomainObject* obj) override;

		void doUpdate(Database* db, DomainObject* obj) override;

		void doRemove(Database* db, DomainObject* obj) override;

	private:
		void bind(SQLite::Statement& query, CE::DataType::Type& type);
	};
};