#include "FunctionTagMapper.h"
#include <Manager/FunctionTagManager.h>
#include <Manager/FunctionDeclManager.h>

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
	return GenerateNextId(&db, "sda_func_decls");
}

IDomainObject* FunctionUserTagMapper::doLoad(Database* db, SQLite::Statement& query)
{
	DB::Id tag_id = query.getColumn("tag_id");
	DB::Id parent_tag_id = query.getColumn("parent_tag_id");

	Tag* parentTag = getManager()->getTagById(parent_tag_id);
	if (parentTag == nullptr)
		return nullptr;

	auto decl = getManager()->getProgramModule()->getFunctionDeclManager()->getFunctionDeclById(query.getColumn("decl_id"));
	if (decl == nullptr)
		return nullptr;

	auto userTag = new UserTag(decl, parentTag, query.getColumn("name"), query.getColumn("desc"));
	userTag->setId(tag_id);
	return userTag;
}

CE::FunctionTagManager* FunctionUserTagMapper::getManager()
{
	return static_cast<CE::FunctionTagManager*>(m_repository);
}

void FunctionUserTagMapper::doInsert(Database* db, IDomainObject* obj)
{
	doUpdate(db, obj);
}

void FunctionUserTagMapper::doUpdate(Database* db, IDomainObject* obj)
{
	auto userTag = static_cast<CE::Function::Tag::UserTag*>(obj);

	SQLite::Statement query(*db, "REPLACE INTO sda_func_tags (tag_id, parent_tag_id, decl_id, name, desc) VALUES(?1, ?2, ?3, ?4, ?5)");
	query.bind(1, userTag->getId());
	bind(query, *userTag);
	query.exec();
}

void FunctionUserTagMapper::doRemove(Database* db, IDomainObject* obj)
{
	Statement query(*db, "DELETE FROM sda_func_tags WHERE tag_id=?1"); //OR parent_tag_id=?1
	query.bind(1, obj->getId());
	query.exec();
}

void FunctionUserTagMapper::bind(SQLite::Statement& query, CE::Function::Tag::UserTag& tag)
{
	query.bind(2, tag.getParent()->getId());
	query.bind(3, tag.isDefinedForDecl() ? tag.getDeclaration()->getId() : 0);
	query.bind(4, tag.getDesc().getName());
	query.bind(5, tag.getDesc().getDesc());
}
