#include "TypedefTypeMapper.h"
#include <Manager/TypeManager.h>

using namespace DB;
using namespace CE;
using namespace CE::DataType;

DomainObject* TypedefTypeMapper::doLoad(Database* db, SQLite::Statement& query)
{
	auto type = new DataType::Typedef(
		getParentMapper()->getManager()->getDefaultType()->getType(),
		query.getColumn("id"),
		query.getColumn("name"),
		query.getColumn("desc")
	);
	return type;
}

void TypedefTypeMapper::doInsert(Database* db, DomainObject* obj)
{
	auto Typedef = static_cast<DataType::Typedef*>(obj);
	SQLite::Statement query(*db, "REPLACE INTO sda_typedefs (type_id, ref_type_id, pointer_lvl, array_size) VALUES(?2, ?3, ?4)");
	bind(query, *Typedef);
	query.exec();
	AbstractMapper::setNewId(db, obj);
}

void TypedefTypeMapper::doUpdate(Database* db, DomainObject* obj)
{
	auto Typedef = static_cast<DataType::Typedef*>(obj);
	SQLite::Statement query(*db, "REPLACE INTO sda_typedefs (type_id, ref_type_id, pointer_lvl, array_size) VALUES(?1, ?2, ?3, ?4)");
	query.bind(1, Typedef->getId());
	bind(query, *Typedef);
	query.exec();
}

void TypedefTypeMapper::doRemove(Database* db, DomainObject* obj)
{
	SQLite::Statement query(*db, "DELETE FROM sda_typedefs WHERE type_id=?1");
	query.bind(1, obj->getId());
	query.exec();
}

void TypedefTypeMapper::bind(SQLite::Statement& query, CE::DataType::Typedef& type)
{
	query.bind(2, type.getRefType()->getId());
	query.bind(3, type.getRefType()->getPointerLvl());
	query.bind(4, type.getRefType()->getArraySize());
}

DataTypeMapper* TypedefTypeMapper::getParentMapper() {
	return static_cast<DataTypeMapper*>(m_parentMapper);
}

