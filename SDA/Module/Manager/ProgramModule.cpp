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

bool ProgramModule::isDll() {
	return !isExe();
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

HMODULE ProgramModule::getHModule() {
	return HMODULE(m_baseAddr);
}

TypeManager* ProgramModule::getTypeManager() {
	return m_typeManager;
}

GVarManager* ProgramModule::getGVarManager() {
	return m_gvarManager;
}

FunctionManager* ProgramModule::getFunctionManager() {
	return m_functionManager;
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

std::uintptr_t ProgramModule::getBaseAddr() {
	return m_baseAddr;
}

void* ProgramModule::toAbsAddr(int offset) {
	return offset == 0 ? nullptr : reinterpret_cast<void*>(getBaseAddr() + (std::uintptr_t)offset);
}

int ProgramModule::toRelAddr(void* addr) {
	return addr == nullptr ? 0 : static_cast<int>((std::uintptr_t)addr - getBaseAddr());
}

DB::ITransaction* ProgramModule::getTransaction() {
	return m_transaction;
}

FS::Directory& ProgramModule::getDirectory() {
	return m_dir;
}

Ghidra::Client* ProgramModule::getGhidraClient() {
	return m_client;
}

ProgramExe::ProgramExe(void* addr, FS::Directory dir)
	: ProgramModule(addr, dir)
{}

bool ProgramExe::isExe() {
	return true;
}

void ProgramExe::addDll(ProgramDll* dll) {
	m_dlls.push_back(dll);
}

std::vector<ProgramDll*>& ProgramExe::getDlls() {
	return m_dlls;
}

ProgramDll::ProgramDll(void* addr, FS::Directory dir)
	: ProgramModule(addr, dir)
{}

bool ProgramDll::isExe() {
	return false;
}
