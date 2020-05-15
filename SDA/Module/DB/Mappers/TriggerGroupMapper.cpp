#include "TriggerGroupMapper.h"
#include <Manager/TriggerManager.h>
#include <Manager/TriggerGroupManager.h>

using namespace DB;
using namespace CE;

TriggerGroupMapper::TriggerGroupMapper(IRepository* repository)
	: AbstractMapper(repository)
{}

void TriggerGroupMapper::loadAll()
{
	auto& db = getManager()->getProgramModule()->getDB();
	Statement query(db, "SELECT * FROM sda_trigger_groups");
	load(&db, query);
}

Id TriggerGroupMapper::getNextId() {
	auto& db = getManager()->getProgramModule()->getDB();
	return GenerateNextId(&db, "sda_trigger_groups");
}

TriggerGroupManager* TriggerGroupMapper::getManager()
{
	return static_cast<TriggerGroupManager*>(m_repository);
}

IDomainObject* TriggerGroupMapper::doLoad(Database* db, SQLite::Statement& query)
{
	auto group = new Trigger::TriggerGroup(
		getManager(),
		query.getColumn("name"),
		query.getColumn("desc")
	);
	group->setId(query.getColumn("group_id"));
	loadTriggersForGroup(db, group);
	return group;
}

void TriggerGroupMapper::saveTriggersForGroup(TransactionContext* ctx, Trigger::TriggerGroup* group) {
	{
		SQLite::Statement query(*ctx->m_db, "DELETE FROM sda_trigger_group_triggers WHERE group_id=?1");
		query.bind(1, group->getId());
		query.exec();
	}

	{
		for (const auto& trigger : group->getTriggers()) {
			SQLite::Statement query(*ctx->m_db, "INSERT INTO sda_trigger_group_triggers (group_id, trigger_id) VALUES(?1, ?2)");
			query.bind(1, group->getId());
			query.bind(2, trigger->getId());
			query.exec();
		}
	}
}

void TriggerGroupMapper::loadTriggersForGroup(Database* db, Trigger::TriggerGroup* group)
{
	using namespace Trigger::Function::Filter;
	SQLite::Statement query(*db, "SELECT trigger_id FROM sda_trigger_group_triggers WHERE group_id=?1");
	query.bind(1, group->getId());

	while (query.executeStep())
	{
		auto trigger = getManager()->getProgramModule()->getTriggerManager()->getTriggerById(query.getColumn("trigger_id"));
		if (trigger != nullptr)
			group->addTrigger(trigger);
	}
}

void TriggerGroupMapper::doInsert(TransactionContext* ctx, IDomainObject* obj)
{
	doUpdate(ctx, obj);
}

void TriggerGroupMapper::doUpdate(TransactionContext* ctx, IDomainObject* obj) {
	auto group = static_cast<Trigger::TriggerGroup*>(obj);
	SQLite::Statement query(*ctx->m_db, "REPLACE INTO sda_trigger_groups(group_id, name, desc) VALUES(?1, ?2, ?3)");
	query.bind(1, group->getId());
	bind(query, *group);
	query.exec();
	saveTriggersForGroup(ctx, group);
}

void TriggerGroupMapper::doRemove(TransactionContext* ctx, IDomainObject* obj)
{
	auto group = static_cast<Trigger::TriggerGroup*>(obj);
	Statement query(*ctx->m_db, "DELETE FROM sda_trigger_groups WHERE group_id=?1");
	query.bind(1, obj->getId());
	query.exec();

	group->getTriggers().clear();
	saveTriggersForGroup(ctx, group);
}

void TriggerGroupMapper::bind(SQLite::Statement& query, Trigger::TriggerGroup& group)
{
	query.bind(2, group.getName());
	query.bind(3, group.getComment());
}
