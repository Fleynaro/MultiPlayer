#include "Manager.h"

void CE::SDA::load()
{
	getTypeManager()->loadTypes();
	getTypeManager()->loadTypedefs();
	getGVarManager()->loadGVars();
	getFunctionManager()->loadFunctions();
	getFunctionManager()->loadFunctionBodies();
	getVTableManager()->loadVTables();
	getTypeManager()->loadClasses();
}

void CE::SDA::initManagers()
{
	m_typeManager = new TypeManager(this);
	m_functionManager = new FunctionManager(this);
	m_gvarManager = new GVarManager(this);
	m_vtableManager = new VtableManager(this);
	m_triggerManager = new TriggerManager(this);
	m_statManager = new StatManager(this);
}

void CE::SDA::initDataBase(std::string filename)
{
	m_db = new SQLite::Database(filename, SQLite::OPEN_READWRITE);
}

void CE::TypeManager::loadInfoForClass(Type::Class* Class)
{
	using namespace SQLite;

	SQLite::Database& db = getSDA()->getDB();
	SQLite::Statement query(db, "SELECT * FROM sda_classes WHERE class_id=?1");
	query.bind(1, Class->getId());
	query.executeStep();

	Function::VTable* vtable = getSDA()->getVTableManager()->getVTableById(query.getColumn("vtable_id"));
	if (vtable != nullptr) {
		Class->setVtable(vtable);
	}
	Type::Class* baseClass = (Type::Class*)getTypeById(query.getColumn("base_class_id"));
	if (baseClass != nullptr) {
		Class->setBaseClass(baseClass);
	}
	Class->resize(query.getColumn("size"));
}

void CE::TypeManager::loadMethodsForClass(Type::Class* Class) {
	using namespace SQLite;

	SQLite::Database& db = getSDA()->getDB();
	SQLite::Statement query(db, "SELECT function_id FROM sda_class_methods WHERE class_id=?1");
	query.bind(1, Class->getId());

	while (query.executeStep())
	{
		Function::Function* function = getSDA()->getFunctionManager()->getFunctionById(query.getColumn("function_id"));
		if (function != nullptr && function->isMethod()) {
			Class->addMethod((Function::Method*)function);
		}
	}
}