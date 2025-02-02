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

Id TriggerMapper::getNextId() {
	auto& db = getManager()->getProgramModule()->getDB();
	return GenerateNextId(&db, "sda_triggers");
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

void TriggerMapper::doInsert(TransactionContext* ctx, IDomainObject* obj)
{
	doUpdate(ctx, obj);
}

void TriggerMapper::doUpdate(TransactionContext* ctx, IDomainObject* obj) {
	auto trigger = static_cast<Trigger::AbstractTrigger*>(obj);
	SQLite::Statement query(*ctx->m_db, "REPLACE INTO sda_triggers(trigger_id, type, name, desc) VALUES(?1, ?2, ?3, ?4)");
	query.bind(1, trigger->getId());
	bind(query, *trigger);
	query.exec();
}

void TriggerMapper::doRemove(TransactionContext* ctx, IDomainObject* obj)
{
	Statement query(*ctx->m_db, "DELETE FROM sda_triggers WHERE trigger_id=?1");
	query.bind(1, obj->getId());
	query.exec();
}

void TriggerMapper::bind(SQLite::Statement& query, Trigger::AbstractTrigger& tr)
{
	query.bind(2, tr.getType());
	query.bind(3, tr.getName());
	query.bind(4, tr.getComment());
}
