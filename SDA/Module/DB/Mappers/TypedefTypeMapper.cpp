#include "TypedefTypeMapper.h"
#include <Manager/TypeManager.h>

using namespace DB;
using namespace CE;
using namespace CE::DataType;

TypedefTypeMapper::TypedefTypeMapper(DataTypeMapper* parentMapper)
	: ChildAbstractMapper(parentMapper)
{}

void TypedefTypeMapper::loadTypedefs(Database * db) {
	SQLite::Statement query(*db, "SELECT * FROM sda_typedefs");

	while (query.executeStep())
	{
		auto type = getParentMapper()->getManager()->getTypeById(query.getColumn("type_id"));
		if (auto Typedef = dynamic_cast<DataType::Typedef*>(type)) {
			auto refType = getParentMapper()->getManager()->getTypeById(query.getColumn("ref_type_id"));
			if (refType != nullptr)
				Typedef->setRefType(DataType::GetUnit(refType, query.getColumn("pointer_lvl")));
		}
	}
}

IDomainObject* TypedefTypeMapper::doLoad(Database* db, SQLite::Statement& query)
{
	auto type = new DataType::Typedef(
		getParentMapper()->getManager(),
		DataType::GetUnit(getParentMapper()->getManager()->getDefaultType()),
		query.getColumn("name"),
		query.getColumn("desc")
	);
	return type;
}

void TypedefTypeMapper::doInsert(Database* db, IDomainObject* obj)
{
	doUpdate(db, obj);
}

void TypedefTypeMapper::doUpdate(Database* db, IDomainObject* obj)
{
	auto Typedef = static_cast<DataType::Typedef*>(obj);
	SQLite::Statement query(*db, "REPLACE INTO sda_typedefs (type_id, ref_type_id, pointer_lvl) VALUES(?1, ?2, ?3)");
	query.bind(1, Typedef->getId());
	bind(query, *Typedef);
	query.exec();
}

void TypedefTypeMapper::doRemove(Database* db, IDomainObject* obj)
{
	SQLite::Statement query(*db, "DELETE FROM sda_typedefs WHERE type_id=?1");
	query.bind(1, obj->getId());
	query.exec();
}

void TypedefTypeMapper::bind(SQLite::Statement& query, CE::DataType::Typedef& type)
{
	query.bind(2, type.getRefType()->getId());
	query.bind(3, DataType::GetPointerLevelStr(type.getRefType()));
}

DataTypeMapper* TypedefTypeMapper::getParentMapper() {
	return static_cast<DataTypeMapper*>(m_parentMapper);
}
