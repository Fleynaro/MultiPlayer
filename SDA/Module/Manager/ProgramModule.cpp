#include "ProgramModule.h"
#include <GhidraSync/GhidraSync.h>
#include <FunctionTag/FunctionTag.h>
#include <Utility/Resource.h>

//managers
#include "Managers.h"

using namespace CE;

ProgramModule::ProgramModule(FS::Directory dir)
	: m_dir(dir)
{
	m_ghidraSync = new Ghidra::Sync(this);
}

ProgramModule::~ProgramModule() {
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

void ProgramModule::initTransaction() {
	m_transaction = new DB::Transaction(m_db);
}

void ProgramModule::load()
{
	getProcessModuleManager()->loadProcessModules();
	getTypeManager()->loadBefore();
	getSymbolManager()->loadSymbols();
	getMemoryAreaManager()->loadSymTables();
	getFunctionManager()->loadFunctions();
	getTypeManager()->loadAfter();
	getFunctionTagManager()->loadUserTags();
	getTriggerManager()->loadTriggers();
	getTriggerGroupManager()->loadTriggerGroups();
}

void ProgramModule::initManagers()
{
	m_processModuleManager = new ProcessModuleManager(this);
	m_typeManager = new TypeManager(this);
	m_functionManager = new FunctionManager(this);
	m_symbolManager = new SymbolManager(this);
	m_memoryAreaManager = new SymbolTableManager(this);
	m_vtableManager = new VtableManager(this);
	m_triggerManager = new TriggerManager(this);
	m_triggerGroupManager = new TriggerGroupManager(this);
	m_statManager = new StatManager(this);
	m_functionManager->setFunctionTagManager(new FunctionTagManager(this, m_functionManager));
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
	auto query = res.getData();
	m_db->exec(query);
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

SQLite::Database& ProgramModule::getDB() {
	return *m_db;
}

ProcessModuleManager* ProgramModule::getProcessModuleManager() {
	return m_processModuleManager;
}

TypeManager* ProgramModule::getTypeManager() {
	return m_typeManager;
}

SymbolManager* ProgramModule::getSymbolManager() {
	return m_symbolManager;
}

SymbolTableManager* ProgramModule::getMemoryAreaManager() {
	return m_memoryAreaManager;
}

FunctionManager* ProgramModule::getFunctionManager() {
	return m_functionManager;
}

FunctionTagManager* ProgramModule::getFunctionTagManager() {
	return m_functionManager->getFunctionTagManager();
}

VtableManager* ProgramModule::getVTableManager() {
	return m_vtableManager;
}

TriggerManager* ProgramModule::getTriggerManager() {
	return m_triggerManager;
}

TriggerGroupManager* ProgramModule::getTriggerGroupManager() {
	return m_triggerGroupManager;
}

StatManager* ProgramModule::getStatManager() {
	return m_statManager;
}

Symbol::SymbolTable* ProgramModule::getGlobalMemoryArea() {
	return getMemoryAreaManager()->getMainGlobalSymTable();
}

DB::ITransaction* ProgramModule::getTransaction() {
	return m_transaction;
}

FS::Directory& ProgramModule::getDirectory() {
	return m_dir;
}

Ghidra::Sync* ProgramModule::getGhidraSync() {
	return m_ghidraSync;
}

