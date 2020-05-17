#include "EnumTypeMapper.h"
#include <Manager/TypeManager.h>
#include <GhidraSync/Mappers/GhidraEnumTypeMapper.h>

using namespace DB;
using namespace CE;
using namespace CE::DataType;

EnumTypeMapper::EnumTypeMapper(DataTypeMapper* parentMapper)
	: ChildAbstractMapper(parentMapper)
{}

IDomainObject* EnumTypeMapper::doLoad(Database* db, SQLite::Statement& query)
{
	auto type = new DataType::Enum(
		getParentMapper()->getManager(),
		query.getColumn("name"),
		query.getColumn("desc")
	);
	type->setId(query.getColumn("id"));
	type->setGhidraMapper(getParentMapper()->getManager()->m_ghidraDataTypeMapper->m_enumTypeMapper);
	loadFieldsForEnum(db, static_cast<DataType::Enum*>(type));
	return type;
}

void EnumTypeMapper::saveEnumFields(TransactionContext* ctx, DataType::Enum* Enum)
{
	{
		SQLite::Statement query(*ctx->m_db, "DELETE FROM sda_enum_fields WHERE enum_id=?1");
		query.bind(1, Enum->getId());
		query.exec();
	}

	{
		for (auto it : Enum->getFieldDict()) {
			SQLite::Statement query(*ctx->m_db, "INSERT INTO sda_enum_fields (enum_id, name, value) VALUES(?1, ?2, ?3)");
			query.bind(1, Enum->getId());
			query.bind(2, it.second);
			query.bind(3, it.first);
			query.exec();
		}
	}
}

void EnumTypeMapper::loadFieldsForEnum(Database* db, DataType::Enum* Enum)
{
	SQLite::Statement query(*db, "SELECT name,value FROM sda_enum_fields WHERE enum_id=?1 GROUP BY value");
	query.bind(1, Enum->getId());

	while (query.executeStep())
	{
		Enum->addField(query.getColumn("name"), query.getColumn("value"));
	}
}

void EnumTypeMapper::doInsert(TransactionContext* ctx, IDomainObject* obj)
{
	doUpdate(ctx, obj);
}

void EnumTypeMapper::doUpdate(TransactionContext* ctx, IDomainObject* obj)
{
	saveEnumFields(ctx, static_cast<DataType::Enum*>(obj));
}

void EnumTypeMapper::doRemove(TransactionContext* ctx, IDomainObject* obj)
{
	if (ctx->m_notDelete)
		return;
}

void EnumTypeMapper::bind(SQLite::Statement& query, CE::DataType::Enum& type)
{
}

DataTypeMapper* EnumTypeMapper::getParentMapper() {
	return static_cast<DataTypeMapper*>(m_parentMapper);
}
