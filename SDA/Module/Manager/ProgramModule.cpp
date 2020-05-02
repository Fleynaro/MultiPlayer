#include "ProgramModule.h"
#include "Manager.h"
#include <GhidraSync/GhidraSync.h>
#include <FunctionTag/FunctionTag.h>
#include <Utility/Resource.h>

using namespace CE;

void ProgramModule::load()
{
	getTypeManager()->loadTypes();
	getTypeManager()->loadTypedefs();
	getGVarManager()->loadGVars();
	getFunctionManager()->loadFunctions();
	getVTableManager()->loadVTables();
	getTypeManager()->loadClasses();
	getFunctionManager()->getFunctionTagManager()->loadTags();
	getTriggerManager()->loadTriggers();
	getTriggerGroupManager()->loadTriggerGroups();
}

void ProgramModule::initManagers()
{
	m_typeManager = new TypeManager(this);
	m_functionManager = new FunctionManager(this, new FunctionDeclManager(this));
	m_gvarManager = new GVarManager(this);
	m_vtableManager = new VtableManager(this);
	m_triggerManager = new TriggerManager(this);
	m_triggerGroupManager = new TriggerGroupManager(this);
	m_statManager = new StatManager(this);
	m_functionManager->setFunctionTagManager(new Function::Tag::Manager(m_functionManager));
}

void ProgramModule::initGhidraClient()
{
	m_client = new Ghidra::Client(this);
	getFunctionManager()->setGhidraManager(m_client->m_functionManager);
	getTypeManager()->setGhidraManager(m_client->m_dataTypeManager);
}

void ProgramModule::createGeneralDataBase()
{
	using namespace SQLite;

	SQL_Res res("SQL_CREATE_GEN_DB", GetModuleHandle(NULL));
	res.load();
	if (!res.isLoaded()) {
		//throw ex
		return;
	}
	m_db->exec(res.getData());
}

void ProgramModule::initDataBase(std::string filename)
{
	auto filedb = FS::File(getDirectory(), filename);
	bool filedbExisting = filedb.exists();
	m_db = new SQLite::Database(filedb.getFilename(), SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE);
	if (!filedbExisting) {
		createGeneralDataBase();
	}
}
