#include "Project.h"
#include <GhidraSync/GhidraSync.h>
#include <Utils/Resource.h>

//managers
#include <Manager/Managers.h>

using namespace CE;

Project::Project(FS::Directory dir)
	: m_dir(dir)
{
	m_ghidraSync = new Ghidra::Sync(this);
}

Project::~Project() {
	if (haveAllManagersBeenLoaded()) {
		delete m_processModuleManager;
		delete m_functionManager;
		delete m_statManager;
		delete m_symbolManager;
		delete m_memoryAreaManager;
		delete m_triggerManager;
		delete m_triggerGroupManager;
		delete m_vtableManager;
		delete m_typeManager;
	}
	if (m_ghidraSync != nullptr) {
		delete m_ghidraSync;
	}
	if (m_transaction != nullptr)
		delete m_transaction;
	if (m_db != nullptr)
		delete m_db;
}

void Project::initTransaction() {
	m_transaction = new DB::Transaction(m_db);
}

void Project::load()
{
	getTypeManager()->loadBefore();
	getSymbolManager()->loadSymbols();
	getMemoryAreaManager()->loadSymTables();
	getFunctionManager()->loadFunctions();
	getTypeManager()->loadAfter();
	getTriggerManager()->loadTriggers();
	getTriggerGroupManager()->loadTriggerGroups();
}

void Project::initManagers()
{
	m_typeManager = new TypeManager(this);
	m_functionManager = new FunctionManager(this);
	m_symbolManager = new SymbolManager(this);
	m_memoryAreaManager = new SymbolTableManager(this);
	m_triggerManager = new TriggerManager(this);
	m_triggerGroupManager = new TriggerGroupManager(this);
	m_statManager = new StatManager(this);
}

void Project::createGeneralDataBase()
{
	using namespace SQLite;

	SQL_Res res("SQL_CREATE_GEN_DB", GetModuleHandle(NULL));
	res.load();
	if (!res.isLoaded()) {
		//throw ex
		return;
	}
	auto query = res.getData();
	m_db->exec(query);
}

void Project::initDataBase(std::string filename)
{
	auto filedb = FS::File(getDirectory(), filename);
	bool filedbExisting = filedb.exists();
	m_db = new SQLite::Database(filedb.getFilename(), SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE);
	if (!filedbExisting) {
		createGeneralDataBase();
	}

	initTransaction();
}

SQLite::Database& Project::getDB() {
	return *m_db;
}

ProcessModuleManager* Project::getProcessModuleManager() {
	return m_processModuleManager;
}

TypeManager* Project::getTypeManager() {
	return m_typeManager;
}

SymbolManager* Project::getSymbolManager() {
	return m_symbolManager;
}

SymbolTableManager* Project::getMemoryAreaManager() {
	return m_memoryAreaManager;
}

FunctionManager* Project::getFunctionManager() {
	return m_functionManager;
}

FunctionTagManager* Project::getFunctionTagManager() {
	return m_functionManager->getFunctionTagManager();
}

VtableManager* Project::getVTableManager() {
	return m_vtableManager;
}

TriggerManager* Project::getTriggerManager() {
	return m_triggerManager;
}

TriggerGroupManager* Project::getTriggerGroupManager() {
	return m_triggerGroupManager;
}

StatManager* Project::getStatManager() {
	return m_statManager;
}

Symbol::SymbolTable* Project::getGlobalMemoryArea() {
	return getMemoryAreaManager()->getMainGlobalSymTable();
}

DB::ITransaction* Project::getTransaction() {
	return m_transaction;
}

FS::Directory& Project::getDirectory() {
	return m_dir;
}

Ghidra::Sync* Project::getGhidraSync() {
	return m_ghidraSync;
}

