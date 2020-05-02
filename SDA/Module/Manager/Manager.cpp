#include "Manager.h"
#include <GhidraSync/GhidraSync.h>
#include <FunctionTag/FunctionTag.h>

#include <Utility/Resource.h>
#include <Program.h>
void createGeneralDataBase(SQLite::Database& db)
{
	using namespace SQLite;
	
	SQL_Res res("SQL_CREATE_GEN_DB", getProgram()->getModule());
	res.load();
	if (!res.isLoaded()) {
		//throw ex
		return;
	}
	db.exec(res.getData());
}

void CE::TypeManager::loadInfoForClass(Type::Class* Class)
{
	using namespace SQLite;

	SQLite::Database& db = getProgramModule()->getDB();
	SQLite::Statement query(db, "SELECT * FROM sda_classes WHERE class_id=?1");
	query.bind(1, Class->getId());
	if (!query.executeStep())
		return;

	Function::VTable* vtable = getProgramModule()->getVTableManager()->getVTableById(query.getColumn("vtable_id"));
	if (vtable != nullptr) {
		Class->setVtable(vtable);
	}
	auto baseClass = getTypeById(query.getColumn("base_class_id"));
	if (baseClass != nullptr) {
		Class->setBaseClass(static_cast<Type::Class*>(baseClass->getType()));
	}
	Class->resize(query.getColumn("size"));
}

void CE::TypeManager::loadMethodsForClass(Type::Class* Class) {
	using namespace SQLite;

	SQLite::Database& db = getProgramModule()->getDB();
	SQLite::Statement query(db, "SELECT decl_id,def_id FROM sda_class_methods WHERE class_id=?1");
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
			auto decl = getProgramModule()->getFunctionManager()->getFunctionDeclManager()->getFunctionDeclById(decl_id);
			if (decl != nullptr && !decl->isFunction()) {
				Class->addMethod((Function::MethodDecl*)decl);
			}
		}
	}
}