#pragma once
#include <DB/AbstractMapper.h>
#include <Code/Type/AbstractType.h>

namespace CE {
	class TypeManager;
};

namespace DB
{
	class EnumTypeMapper;
	class StructureTypeMapper;
	class ClassTypeMapper;
	class TypedefTypeMapper;

	class DataTypeMapper : public AbstractMapper
	{
	public:
		EnumTypeMapper* m_enumTypeMapper;
		StructureTypeMapper* m_structureTypeMapper;
		ClassTypeMapper* m_classTypeMapper;
		TypedefTypeMapper* m_typedefTypeMapper;

		DataTypeMapper(IRepository* repository);

		void loadAll();

		void loadStructsAndClasses();

		CE::TypeManager* getManager();
	protected:
		IDomainObject* doLoad(Database* db, SQLite::Statement& query) override;

		void doInsert(Database* db, IDomainObject* obj) override;

		void doUpdate(Database* db, IDomainObject* obj) override;

		void doRemove(Database* db, IDomainObject* obj) override;

	private:
		void bind(SQLite::Statement& query, CE::DataType::Type& type);
	};
};