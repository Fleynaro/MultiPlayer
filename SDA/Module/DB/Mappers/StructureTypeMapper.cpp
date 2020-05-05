#include "StructureTypeMapper.h"
#include <Manager/TypeManager.h>
#include <Code/Type/Structure.h>

using namespace DB;
using namespace CE;

StructureTypeMapper::StructureTypeMapper(DataTypeMapper* parentMapper)
	: ChildAbstractMapper(parentMapper)
{}

void StructureTypeMapper::loadStructures(Database * db) {
	SQLite::Statement query(*db, "SELECT * FROM sda_structures");

	while (query.executeStep())
	{
		auto type = getParentMapper()->getManager()->getTypeById(query.getColumn("struct_id"));
		if (auto structure = dynamic_cast<DataType::Structure*>(type)) {
			structure->resize(query.getColumn("size"));
			loadFieldsForStructure(db, structure);
		}
	}
}

IDomainObject* StructureTypeMapper::doLoad(Database* db, SQLite::Statement& query) {
	auto type = new DataType::Structure(
		getParentMapper()->getManager(),
		query.getColumn("name"),
		query.getColumn("desc")
	);
	return type;
}

void StructureTypeMapper::loadFieldsForStructure(Database* db, CE::DataType::Structure* structure) {
	SQLite::Statement query(*db, "SELECT * FROM sda_struct_fields WHERE struct_id=?1");
	query.bind(1, structure->getId());

	while (query.executeStep())
	{
		auto type = getParentMapper()->getManager()->getProgramModule()->getTypeManager()->getTypeById(query.getColumn("type_id"));
		if (type == nullptr) {
			type = getParentMapper()->getManager()->getProgramModule()->getTypeManager()->getDefaultType();
		}

		structure->addField(query.getColumn("offset"), query.getColumn("name"), DataType::GetUnit(type, query.getColumn("pointer_lvl")));
	}
}

void StructureTypeMapper::saveFieldsForStructure(Database* db, CE::DataType::Structure* structure) {
	{
		SQLite::Statement query(*db, "DELETE FROM sda_struct_fields WHERE struct_id=?1");
		query.bind(1, structure->getId());
		query.exec();
	}

	{
		for (auto& it : structure->getFields()) {
			auto field = it.second;
			SQLite::Statement query(*db, "INSERT INTO sda_struct_fields (struct_id, offset, name, type_id, pointer_lvl) VALUES(?1, ?2, ?3, ?4, ?5)");
			query.bind(1, structure->getId());
			query.bind(2, field->getOffset());
			query.bind(3, field->getName());
			query.bind(4, field->getType()->getId());
			query.bind(5, DataType::GetPointerLevelStr(field->getType()));
			query.exec();
		}
	}
}

void StructureTypeMapper::doInsert(Database* db, IDomainObject* obj)
{
	doUpdate(db, obj);
}

void StructureTypeMapper::doUpdate(Database* db, IDomainObject* obj)
{
	auto structure = static_cast<DataType::Structure*>(obj);
	SQLite::Statement query(*db, "REPLACE INTO sda_structures (struct_id, size) VALUES(?1, ?2)");
	query.bind(1, structure->getId());
	bind(query, *structure);
	query.exec();
	saveFieldsForStructure(db, structure);
}

void StructureTypeMapper::doRemove(Database* db, IDomainObject* obj)
{
	SQLite::Statement query(*db, "DELETE FROM sda_structures WHERE struct_id=?1");
	query.bind(1, obj->getId());
	query.exec();
}

void StructureTypeMapper::bind(SQLite::Statement& query, CE::DataType::Structure& structure) {
	query.bind(2, structure.getSize());
}

DataTypeMapper* StructureTypeMapper::getParentMapper() {
	return static_cast<DataTypeMapper*>(m_parentMapper);
}
