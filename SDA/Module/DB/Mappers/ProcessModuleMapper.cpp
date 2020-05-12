#include "ProcessModuleMapper.h"
#include <Manager/ProcessModuleManager.h>

using namespace CE;
using namespace DB;


ProcessModuleMapper::ProcessModuleMapper(ProcessModuleManager* manager)
	: AbstractMapper(manager)
{}

void ProcessModuleMapper::loadAll()
{
	auto& db = getManager()->getProgramModule()->getDB();
	Statement query(db, "SELECT * FROM sda_process_modules WHERE module_id >= 2");
	load(&db, query);
}

Id ProcessModuleMapper::getNextId()
{
	auto& db = getManager()->getProgramModule()->getDB();
	return GenerateNextId(&db, "sda_process_modules");
}

ProcessModuleManager* ProcessModuleMapper::getManager()
{
	return static_cast<ProcessModuleManager*>(m_repository);
}

IDomainObject* ProcessModuleMapper::doLoad(Database* db, SQLite::Statement& query)
{
	IDomainObject* obj = nullptr;
	std::string moduleName = query.getColumn("name");
	obj = new ProccessModule(
		getManager(),
		GetModuleHandle(moduleName.c_str()),
		moduleName,
		query.getColumn("desc")
	);
	obj->setId(query.getColumn("module_id"));
	return obj;
}

void ProcessModuleMapper::doInsert(Database* db, IDomainObject* obj)
{
	doUpdate(db, obj);
}

void ProcessModuleMapper::doUpdate(Database* db, IDomainObject* obj)
{
	auto module = static_cast<ProccessModule*>(obj);
	SQLite::Statement query(*db, "REPLACE INTO sda_process_modules(module_id, name, desc) VALUES(?1, ?2, ?3)");
	query.bind(1, module->getId());
	bind(query, *module);
	query.exec();
}

void ProcessModuleMapper::doRemove(Database* db, IDomainObject* obj)
{
	Statement query(*db, "DELETE FROM sda_process_modules WHERE module_id=?1");
	query.bind(1, obj->getId());
	query.exec();
}

void ProcessModuleMapper::bind(SQLite::Statement& query, CE::ProccessModule& module)
{
	query.bind(2, module.getName());
	query.bind(3, module.getComment());
}
