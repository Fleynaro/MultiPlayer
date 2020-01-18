#include "Manager.h"
#include <GhidraSync/GhidraSync.h>

void CE::ProgramModule::load()
{
	getTypeManager()->loadTypes();
	getTypeManager()->loadTypedefs();
	getGVarManager()->loadGVars();
	getFunctionManager()->loadFunctions();
	getFunctionManager()->loadFunctionBodies();
	getVTableManager()->loadVTables();
	getTypeManager()->loadClasses();
}

void CE::ProgramModule::initManagers()
{
	m_typeManager = new TypeManager(this);
	m_functionManager = new FunctionManager(this);
	m_gvarManager = new GVarManager(this);
	m_vtableManager = new VtableManager(this);
	m_triggerManager = new TriggerManager(this);
	m_statManager = new StatManager(this);
}

void CE::ProgramModule::initGhidraClient()
{
	m_client = new Ghidra::Client(this);
}

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

void CE::ProgramModule::initDataBase(std::string relPath)
{
	auto filedb = FS::File(getDirectory(), relPath);
	bool filedbExisting = filedb.exists();
	m_db = new SQLite::Database(filedb.getFilename(), SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE);
	if (!filedbExisting) {
		createGeneralDataBase(*m_db);
	}
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
	SQLite::Statement query(db, "SELECT function_id FROM sda_class_methods WHERE class_id=?1");
	query.bind(1, Class->getId());

	while (query.executeStep())
	{
		auto function = getProgramModule()->getFunctionManager()->getFunctionById(query.getColumn("function_id"));
		if (function != nullptr && function->getFunction()->isMethod()) {
			Class->addMethod(static_cast<Function::Method*>(function->getFunction()));
		}
	}
}