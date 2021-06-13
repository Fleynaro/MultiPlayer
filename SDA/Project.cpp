#include "Project.h"
#include <GhidraSync/GhidraSync.h>
#include <Utils/Resource.h>

//managers
#include <Manager/Managers.h>

using namespace CE;

Project::Project(const fs::path& dir)
	: m_directory(dir)
{
	m_ghidraSync = new Ghidra::Sync(this);
}

Project::~Project() {
	if (m_haveAllManagersBeenLoaded) {
		delete m_functionManager;
		delete m_statManager;
		delete m_symbolManager;
		delete m_symbolTableManager;
		delete m_triggerManager;
		delete m_triggerGroupManager;
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
	getSymTableManager()->loadSymTables();
	getFunctionManager()->loadFunctions();
	getTypeManager()->loadAfter();
	getAddrSpaceManager()->loadAddressSpaces();
	getImageManager()->loadImages();
	getTriggerManager()->loadTriggers();
	getTriggerGroupManager()->loadTriggerGroups();
}

void Project::initManagers()
{
	m_typeManager = new TypeManager(this);
	m_functionManager = new FunctionManager(this);
	m_symbolManager = new SymbolManager(this);
	m_symbolTableManager = new SymbolTableManager(this);
	m_addrSpaceManager = new AddressSpaceManager(this);
	m_imageManager = new ImageManager(this);
	m_triggerManager = new TriggerManager(this);
	m_triggerGroupManager = new TriggerGroupManager(this);
	m_statManager = new StatManager(this);
	m_haveAllManagersBeenLoaded = true;
}

void CE::Project::createTablesInDatabase()
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

void CE::Project::initDataBase(const fs::path& file)
{
	auto filedb = m_directory / file;
	bool filedbExisting = fs::exists(filedb);

	// init database
	m_db = new SQLite::Database(filedb.string(), SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE);
	
	// if data base didn't exist then create tables
	if (!filedbExisting) {
		createTablesInDatabase();
	}

	initTransaction();
}

SQLite::Database& Project::getDB() {
	return *m_db;
}

TypeManager* Project::getTypeManager() {
	return m_typeManager;
}

SymbolManager* Project::getSymbolManager() {
	return m_symbolManager;
}

SymbolTableManager* Project::getSymTableManager() {
	return m_symbolTableManager;
}

FunctionManager* Project::getFunctionManager() {
	return m_functionManager;
}

AddressSpaceManager* CE::Project::getAddrSpaceManager() {
	return m_addrSpaceManager;
}

ImageManager* CE::Project::getImageManager() {
	return m_imageManager;
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
	return getSymTableManager()->getMainGlobalSymTable();
}

DB::ITransaction* Project::getTransaction() {
	return m_transaction;
}

const fs::path& CE::Project::getDirectory() {
	return m_directory;
}

const fs::path& CE::Project::getImagesDirectory() {
	return m_directory / fs::path("images");
}

Ghidra::Sync* Project::getGhidraSync() {
	return m_ghidraSync;
}

