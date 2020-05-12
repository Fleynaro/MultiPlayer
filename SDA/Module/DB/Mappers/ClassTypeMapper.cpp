#include "ClassTypeMapper.h"
#include <Code/Type/Class.h>
#include <Manager/TypeManager.h>
#include <Manager/FunctionDefManager.h>
#include <Manager/VTableManager.h>

using namespace DB;
using namespace CE;

ClassTypeMapper::ClassTypeMapper(StructureTypeMapper* parentMapper)
	: ChildAbstractMapper(parentMapper)
{}

void ClassTypeMapper::loadClasses(Database* db)
{
	SQLite::Statement query(*db, "SELECT * FROM sda_classes");

	while (query.executeStep())
	{
		auto type = getParentMapper()->getManager()->getTypeById(query.getColumn("struct_id"));
		if (auto Class = dynamic_cast<DataType::Class*>(type)) {
			Function::VTable* vtable = getParentMapper()->getManager()->getProgramModule()->getVTableManager()->getVTableById(query.getColumn("vtable_id"));
			if (vtable != nullptr) {
				Class->setVtable(vtable);
			}
			
			type = getParentMapper()->getManager()->getTypeById(query.getColumn("base_struct_id"));
			if (auto baseClass = dynamic_cast<DataType::Class*>(type)) {
				Class->setBaseClass(baseClass, false);
			}

			loadMethodsForClass(db, Class);
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

void ClassTypeMapper::loadMethodsForClass(Database* db, DataType::Class* Class)
{
	SQLite::Statement query(*db, "SELECT decl_id FROM sda_class_methods WHERE struct_id=?1");
	query.bind(1, Class->getId());

	while (query.executeStep())
	{
		auto decl = getParentMapper()->getManager()->getProgramModule()->getFunctionManager()->getFunctionDeclManager()->getFunctionDeclById(query.getColumn("decl_id"));
		if (auto methodDecl = dynamic_cast<Function::MethodDecl*>(decl)) {
			Class->addMethod(methodDecl);
		}
	}
}

void ClassTypeMapper::saveMethodsForClass(Database* db, DataType::Class* Class)
{
	{
		SQLite::Statement query(*db, "DELETE FROM sda_class_methods WHERE struct_id=?1");
		query.bind(1, Class->getId());
		query.exec();
	}

	{
		for (auto method : Class->getMethods()) {
			SQLite::Statement query(*db, "INSERT INTO sda_class_methods (struct_id, decl_id) VALUES(?1, ?2)");
			query.bind(1, Class->getId());
			query.bind(2, method->getId());
			query.exec();
		}
	}
}

void ClassTypeMapper::doInsert(Database* db, IDomainObject* obj)
{
	doUpdate(db, obj);
}

void ClassTypeMapper::doUpdate(Database* db, IDomainObject* obj)
{
	auto Class = static_cast<DataType::Class*>(obj);

	SQLite::Statement query(*db, "REPLACE INTO sda_classes (struct_id, base_struct_id, vtable_id) VALUES(?1, ?2, ?3)");
	query.bind(1, Class->getId());
	bind(query, *Class);
	query.exec();
	saveMethodsForClass(db, Class);
}

void ClassTypeMapper::doRemove(Database* db, IDomainObject* obj)
{
	SQLite::Statement query(*db, "DELETE FROM sda_classes WHERE struct_id=?1");
	query.bind(1, obj->getId());
	query.exec();
}

void ClassTypeMapper::bind(SQLite::Statement& query, CE::DataType::Class& type)
{
	query.bind(2, type.getBaseClass() != nullptr ? type.getBaseClass()->getId() : 0);
	auto vtable = type.getVtable();
	//query.bind(3, vtable == nullptr ? 0 : vtable->getId());
}

DataTypeMapper* ClassTypeMapper::getParentMapper() {
	return static_cast<StructureTypeMapper*>(m_parentMapper)->getParentMapper();
}
