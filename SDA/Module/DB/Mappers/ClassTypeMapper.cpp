#include "ClassTypeMapper.h"
#include <Code/Type/Class.h>
#include <Manager/TypeManager.h>
#include <Manager/FunctionDefManager.h>
#include <Manager/VTableManager.h>

using namespace DB;
using namespace CE;

void ClassTypeMapper::loadClasses(Database* db)
{
	TypeManager::Iterator it(getParentMapper()->getManager());
	while (it.hasNext()) {
		auto type = it.next();
		if (auto Class = dynamic_cast<DataType::Class*>(type)) {
			loadInfoForClass(db, Class);
			loadMethodsForClass(db, Class);
			loadFieldsForClass(db, Class);
		}
	}
}

IDomainObject* ClassTypeMapper::doLoad(Database* db, SQLite::Statement& query)
{
	auto type = new DataType::Class(
		getParentMapper()->getManager(),
		query.getColumn("name"),
		query.getColumn("desc")
	);
	return type;
}

void DB::ClassTypeMapper::loadInfoForClass(Database* db, DataType::Class* Class)
{
	SQLite::Statement query(*db, "SELECT * FROM sda_classes WHERE class_id=?1");
	query.bind(1, Class->getId());
	if (!query.executeStep())
		return;

	Function::VTable* vtable = getParentMapper()->getManager()->getProgramModule()->getVTableManager()->getVTableById(query.getColumn("vtable_id"));
	if (vtable != nullptr) {
		Class->setVtable(vtable);
	}
	auto baseClass = getParentMapper()->getManager()->getTypeById(query.getColumn("base_class_id"));
	if (baseClass != nullptr) {
		Class->setBaseClass(static_cast<DataType::Class*>(baseClass));
	}
	Class->resize(query.getColumn("size"));
}

void ClassTypeMapper::loadMethodsForClass(Database* db, DataType::Class* Class)
{
	SQLite::Statement query(*db, "SELECT decl_id,def_id FROM sda_class_methods WHERE class_id=?1");
	query.bind(1, Class->getId());

	while (query.executeStep())
	{
		int def_id = query.getColumn("def_id");
		if (def_id != 0) {
			/*auto function = getProgramModule()->getFunctionManager()->getFunctionById(def_id);
			if (function != nullptr && !function->getFunction()->isFunction()) {
			Class->addMethod(function->getMethod());
			}*/
		}
		else {
			int decl_id = query.getColumn("decl_id");
			auto decl = getParentMapper()->getManager()->getProgramModule()->getFunctionManager()->getFunctionDeclManager()->getFunctionDeclById(decl_id);
			if (decl != nullptr && !decl->isFunction()) {
				Class->addMethod((Function::MethodDecl*)decl);
			}
		}
	}
}

void ClassTypeMapper::loadFieldsForClass(Database* db, DataType::Class* Class) {
	SQLite::Statement query(*db, "SELECT * FROM sda_class_fields WHERE class_id=?1 GROUP BY rel_offset");
	query.bind(1, Class->getId());

	while (query.executeStep())
	{
		DataType::Type* type = getParentMapper()->getManager()->getProgramModule()->getTypeManager()->getType(
			query.getColumn("type_id"),
			query.getColumn("pointer_lvl"),
			query.getColumn("array_size")
		);

		if (type == nullptr) {
			type = getParentMapper()->getManager()->getProgramModule()->getTypeManager()->getDefaultType();
		}
		Class->addField(query.getColumn("rel_offset"), query.getColumn("name"), type);
	}
}

void ClassTypeMapper::saveClassFields(Database* db, DataType::Class* Class)
{
	{
		SQLite::Statement query(*db, "DELETE FROM sda_class_fields WHERE class_id=?1");
		query.bind(1, Class->getId());
		query.exec();
	}

	{
		Class->iterateFields([&](int offset, DataType::Class::Field* field) {
			SQLite::Statement query(*db, "INSERT INTO sda_class_fields (class_id, rel_offset, name, type_id, pointer_lvl, array_size) VALUES(?1, ?2, ?3, ?4, ?5, ?6)");
			query.bind(1, Class->getId());
			query.bind(2, offset);
			query.bind(3, field->getName());
			query.bind(4, field->getType()->getId());
			query.bind(5, field->getType()->getPointerLvl());
			query.bind(6, field->getType()->getArraySize());
			query.exec();
			return true;
			});
	}
}

void ClassTypeMapper::saveClassMethods(Database* db, DataType::Class* Class)
{
	{
		SQLite::Statement query(*db, "DELETE FROM sda_class_methods WHERE class_id=?1");
		query.bind(1, Class->getId());
		query.exec();
	}

	{
		for (auto method : Class->getMethodList()) {
			SQLite::Statement query(*db, "INSERT INTO sda_class_fields (class_id, function_id) VALUES(?1, ?2)");
			query.bind(1, Class->getId());
			query.bind(2, method->getId());
			query.exec();
		}
	}
}

void ClassTypeMapper::doInsert(Database* db, IDomainObject* obj)
{
	auto Class = static_cast<DataType::Class*>(obj);
	SQLite::Statement query(*db, "INSERT INTO sda_classes (base_class_id, size, vtable_id) VALUES(?2, ?3, ?4)");
	bind(query, *Class);
	query.exec();
	AbstractMapper::setNewId(db, obj);
}

void ClassTypeMapper::doUpdate(Database* db, IDomainObject* obj)
{
	auto Class = static_cast<DataType::Class*>(obj);
	SQLite::Statement query(*db, "REPLACE INTO sda_classes (class_id, base_class_id, size, vtable_id) VALUES(?1, ?2, ?3, ?4)");
	query.bind(1, Class->getId());
	bind(query, *Class);
	query.exec();
}

void ClassTypeMapper::doRemove(Database* db, IDomainObject* obj)
{
	SQLite::Statement query(*db, "DELETE FROM sda_classes WHERE class_id=?1");
	query.bind(1, obj->getId());
	query.exec();
}

void ClassTypeMapper::bind(SQLite::Statement& query, CE::DataType::Class& type)
{
	query.bind(2, type.getBaseClass() != nullptr ? type.getBaseClass()->getId() : 0);
	query.bind(3, type.getRelSize());
	auto vtable = type.getVtable();
	query.bind(4, vtable == nullptr ? 0 : vtable->getId());
}

DataTypeMapper* ClassTypeMapper::getParentMapper() {
	return static_cast<DataTypeMapper*>(m_parentMapper);
}
