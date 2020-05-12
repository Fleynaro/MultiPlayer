#include "DataTypeMapper.h"
#include "EnumTypeMapper.h"
#include "StructureTypeMapper.h"
#include "ClassTypeMapper.h"
#include "TypedefTypeMapper.h"
#include <Manager/TypeManager.h>

using namespace DB;
using namespace CE;
using namespace CE::DataType;


DataTypeMapper::DataTypeMapper(IRepository* repository)
	: AbstractMapper(repository)
{
	m_enumTypeMapper = new EnumTypeMapper(this);
	m_structureTypeMapper = new StructureTypeMapper(this);
	m_classTypeMapper = new ClassTypeMapper(m_structureTypeMapper);
	m_typedefTypeMapper = new TypedefTypeMapper(this);
}

void DataTypeMapper::loadAll() {
	auto& db = getManager()->getProgramModule()->getDB();
	Statement query(db, "SELECT * FROM sda_types WHERE id >= 1000");
	load(&db, query);

	m_typedefTypeMapper->loadTypedefs(&db);
}

void DataTypeMapper::loadStructsAndClasses() {
	auto& db = getManager()->getProgramModule()->getDB();
	m_structureTypeMapper->loadStructures(&db);
	m_classTypeMapper->loadClasses(&db);
}

Id DataTypeMapper::getNextId() {
	auto& db = getManager()->getProgramModule()->getDB();
	return GenerateNextId(&db, "sda_types");
}

CE::TypeManager* DataTypeMapper::getManager() {
	return static_cast<CE::TypeManager*>(m_repository);
}

IDomainObject* DataTypeMapper::doLoad(Database* db, SQLite::Statement& query) {
	IDomainObject* obj = nullptr;

	int group = query.getColumn("group");
	switch (group)
	{
	case DataType::Type::Group::Typedef:
		obj = m_typedefTypeMapper->doLoad(db, query);
		break;
	case DataType::Type::Group::Enum:
		obj = m_enumTypeMapper->doLoad(db, query);
		break;
	case DataType::Type::Group::Structure:
		obj = m_structureTypeMapper->doLoad(db, query);
		break;
	case DataType::Type::Group::Class:
		obj = m_classTypeMapper->doLoad(db, query);
		break;
	}

	if (obj != nullptr)
		obj->setId(query.getColumn("id"));
	return obj;
}

void DataTypeMapper::doInsert(Database* db, IDomainObject* obj) {
	doUpdate(db, obj);
}

void DataTypeMapper::doUpdate(Database* db, IDomainObject* obj) {
	auto type = static_cast<CE::DataType::Type*>(obj);
	SQLite::Statement query(*db, "REPLACE INTO sda_types (id, `group`, name, desc) VALUES(?1, ?2, ?3, ?4)");
	query.bind(1, type->getId());
	bind(query, *type);
	query.exec();
}

void DataTypeMapper::doRemove(Database* db, IDomainObject* obj) {
	SQLite::Statement query(*db, "DELETE FROM sda_types WHERE id=?1");
	query.bind(1, obj->getId());
	query.exec();
}

void DataTypeMapper::bind(SQLite::Statement& query, CE::DataType::Type& type)
{
	query.bind(2, (int)type.getGroup());
	query.bind(3, type.getName());
	query.bind(4, type.getComment());
}
