#include "TriggerMapper.h"
#include "FunctionTriggerMapper.h"
#include <Manager/TriggerManager.h>

using namespace DB;
using namespace CE;

TriggerMapper::TriggerMapper(IRepository* repository)
	: AbstractMapper(repository)
{
	m_functionTriggerMapper = new FunctionTriggerMapper(this);
}

void TriggerMapper::loadAll()
{
	auto& db = getManager()->getProgramModule()->getDB();
	Statement query(db, "SELECT * FROM sda_triggers");
	load(&db, query);
}

TriggerManager* TriggerMapper::getManager()
{
	return static_cast<TriggerManager*>(m_repository);
}

IDomainObject* TriggerMapper::doLoad(Database* db, SQLite::Statement& query)
{
	IDomainObject* obj = nullptr;

	int type = query.getColumn("type");
	switch (type)
	{
	case Trigger::FunctionTrigger:
		obj = m_functionTriggerMapper->doLoad(db, query);
		break;
	}
	
	if (obj != nullptr)
		obj->setId(query.getColumn("trigger_id"));
	return obj;
}

void TriggerMapper::doInsert(Database* db, IDomainObject* obj)
{
	auto trigger = static_cast<Trigger::AbstractTrigger*>(obj);
	SQLite::Statement query(*db, "INSERT INTO sda_triggers(type, name, desc) VALUES(?2, ?3, ?4)");
	bind(query, *trigger);
	query.exec();
	setNewId(db, obj);
}

void TriggerMapper::doUpdate(Database* db, IDomainObject* obj) {
	auto trigger = static_cast<Trigger::AbstractTrigger*>(obj);
	SQLite::Statement query(*db, "REPLACE INTO sda_triggers(trigger_id, type, name, desc) VALUES(?1, ?2, ?3, ?4)");
	query.bind(1, trigger->getId());
	bind(query, *trigger);
	query.exec();
}

void TriggerMapper::doRemove(Database* db, IDomainObject* obj)
{
	Statement query(*db, "DELETE FROM sda_triggers WHERE trigger_id=?1");
	query.bind(1, obj->getId());
	query.exec();
}

void TriggerMapper::bind(SQLite::Statement& query, Trigger::AbstractTrigger& tr)
{
	query.bind(2, tr.getType());
	query.bind(3, tr.getDesc().getName());
	query.bind(4, tr.getDesc().getDesc());
}
