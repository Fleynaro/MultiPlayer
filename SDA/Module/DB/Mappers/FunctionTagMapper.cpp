#include "FunctionTagMapper.h"
#include <Manager/FunctionTagManager.h>
#include <Manager/FunctionManager.h>

using namespace CE;
using namespace DB;

FunctionUserTagMapper::FunctionUserTagMapper(FunctionTagManager* manager)
	: AbstractMapper(manager)
{
}

void FunctionUserTagMapper::loadAll()
{
	auto& db = getManager()->getProgramModule()->getDB();
	Statement query(db, "SELECT * FROM sda_func_tags WHERE tag_id >= 3 ORDER BY parent_tag_id ASC, tag_id ASC");
	load(&db, query);
}

Id FunctionUserTagMapper::getNextId() {
	auto& db = getManager()->getProgramModule()->getDB();
	return GenerateNextId(&db, "sda_func_tags");
}

IDomainObject* FunctionUserTagMapper::doLoad(Database* db, SQLite::Statement& query)
{
	DB::Id tag_id = query.getColumn("tag_id");
	DB::Id parent_tag_id = query.getColumn("parent_tag_id");

	Tag* parentTag = getManager()->getTagById(parent_tag_id);
	if (parentTag == nullptr)
		return nullptr;

	auto func = getManager()->getProgramModule()->getFunctionManager()->getFunctionById(query.getColumn("func_id"));
	if (func == nullptr)
		return nullptr;

	auto userTag = new UserTag(func, parentTag, query.getColumn("name"), query.getColumn("desc"));
	userTag->setId(tag_id);
	return userTag;
}

CE::FunctionTagManager* FunctionUserTagMapper::getManager()
{
	return static_cast<CE::FunctionTagManager*>(m_repository);
}

void FunctionUserTagMapper::doInsert(TransactionContext* ctx, IDomainObject* obj)
{
	doUpdate(ctx, obj);
}

void FunctionUserTagMapper::doUpdate(TransactionContext* ctx, IDomainObject* obj)
{
	auto userTag = static_cast<CE::Function::Tag::UserTag*>(obj);

	SQLite::Statement query(*ctx->m_db, "REPLACE INTO sda_func_tags (tag_id, parent_tag_id, func_id, name, desc) VALUES(?1, ?2, ?3, ?4, ?5)");
	query.bind(1, userTag->getId());
	bind(query, *userTag);
	query.exec();
}

void FunctionUserTagMapper::doRemove(TransactionContext* ctx, IDomainObject* obj)
{
	Statement query(*ctx->m_db, "DELETE FROM sda_func_tags WHERE tag_id=?1"); //OR parent_tag_id=?1
	query.bind(1, obj->getId());
	query.exec();
}

void FunctionUserTagMapper::bind(SQLite::Statement& query, CE::Function::Tag::UserTag& tag)
{
	query.bind(2, tag.getParent()->getId());
	query.bind(3, tag.isDefinedForFunc() ? tag.getId() : 0);
	query.bind(4, tag.getName());
	query.bind(5, tag.getComment());
}
