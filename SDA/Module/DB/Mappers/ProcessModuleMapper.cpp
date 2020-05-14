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
	std::string fileName = query.getColumn("filename");
	obj = new ProcessModule(
		getManager(),
		GetModuleHandle(fileName.c_str()),
		query.getColumn("name"),
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
	auto module = static_cast<ProcessModule*>(obj);
	SQLite::Statement query(*db, "REPLACE INTO sda_process_modules(module_id, filename, name, desc) VALUES(?1, ?2, ?3, ?4)");
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

void ProcessModuleMapper::bind(SQLite::Statement& query, CE::ProcessModule& module)
{
	query.bind(2, module.getFile().getFilename());
	query.bind(3, module.getName());
	query.bind(4, module.getComment());
}
