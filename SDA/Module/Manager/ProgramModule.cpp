#include "ProgramModule.h"
#include "Manager.h"
#include <GhidraSync/GhidraSync.h>
#include <FunctionTag/FunctionTag.h>
#include <Utility/Resource.h>

using namespace CE;

ProgramModule::ProgramModule(void* addr, FS::Directory dir)
	: m_baseAddr((std::uintptr_t)addr), m_dir(dir)
{}

ProgramModule::~ProgramModule() {
	if (m_typeManager != nullptr) {
		delete m_functionManager;
		delete m_statManager;
		delete m_gvarManager;
		delete m_triggerManager;
		delete m_triggerGroupManager;
		delete m_vtableManager;
		delete m_typeManager;
	}
	if (m_client != nullptr) {
		delete m_client;
	}
	if (m_transaction != nullptr)
		delete m_transaction;
	if (m_db != nullptr)
		delete m_db;
}

void ProgramModule::remove() {
	if (m_db == nullptr)
		return;
	auto file = FS::File(m_db->getFilename());
	delete m_db;
	m_db = nullptr;
	if (file.remove()) {
	}
}

void ProgramModule::initTransaction() {
	m_transaction = new DB::Transaction(m_db);
}

void ProgramModule::load()
{
	getTypeManager()->loadTypes();
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
	
	Database db(m_db->getFilename(), SQLite::OPEN_READWRITE);
	db.exec("UPDATE SQLITE_SEQUENCE SET seq = 1000 WHERE name = 'sda_types'");
	auto c = db.getTotalChanges();
	c = 0;
}

void ProgramModule::initDataBase(std::string filename)
{
	auto filedb = FS::File(getDirectory(), filename);
	bool filedbExisting = filedb.exists();
	m_db = new SQLite::Database(filedb.getFilename(), SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE);
	if (!filedbExisting) {
		createGeneralDataBase();
	}

	initTransaction();
}
