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
	class SignatureTypeMapper;

	class DataTypeMapper : public AbstractMapper
	{
	public:
		EnumTypeMapper* m_enumTypeMapper;
		StructureTypeMapper* m_structureTypeMapper;
		ClassTypeMapper* m_classTypeMapper;
		TypedefTypeMapper* m_typedefTypeMapper;
		SignatureTypeMapper* m_signatureTypeMapper;

		DataTypeMapper(IRepository* repository);

		void loadAll();

		void loadStructsAndClasses();

		Id getNextId() override;

		CE::TypeManager* getManager();
	protected:
		IDomainObject* doLoad(Database* db, SQLite::Statement& query) override;

		void doInsert(TransactionContext* ctx, IDomainObject* obj) override;

		void doUpdate(TransactionContext* ctx, IDomainObject* obj) override;

		void doRemove(TransactionContext* ctx, IDomainObject* obj) override;

	private:
		void bind(SQLite::Statement& query, CE::DataType::Type& type);
	};
};