#include "AbstractMapper.h"

using namespace SQLite;

DB::AbstractMapper::AbstractMapper(IRepository* repository)
	: m_repository(repository)
{}

void DB::AbstractMapper::load(Database* db, Statement& query) {
	while (query.executeStep())
	{
		auto obj = doLoad(db, query);
		if (obj != nullptr) {
			if (m_repository != nullptr)
				m_repository->onLoaded(obj);
			obj->setMapper(this);
		}
	}
}

void DB::AbstractMapper::insert(TransactionContext* ctx, IDomainObject* obj) {
	if (m_repository != nullptr)
		m_repository->onChangeAfterCommit(obj, IRepository::Inserted);
	doInsert(ctx, obj);
}

void DB::AbstractMapper::update(TransactionContext* ctx, IDomainObject* obj) {
	if (m_repository != nullptr)
		m_repository->onChangeAfterCommit(obj, IRepository::Updated);
	doUpdate(ctx, obj);
}

void DB::AbstractMapper::remove(TransactionContext* ctx, IDomainObject* obj) {
	if (m_repository != nullptr)
		m_repository->onChangeAfterCommit(obj, IRepository::Removed);
	doRemove(ctx, obj);
}

DB::IRepository* DB::AbstractMapper::getRepository() {
	return m_repository;
}

DB::IDomainObject* DB::AbstractMapper::find(Id id) {
	return m_repository->find(id);
}

DB::Id DB::GenerateNextId(Database* db, const std::string& tableName) {
	SQLite::Statement query(*db, "SELECT seq FROM SQLITE_SEQUENCE WHERE name=?1");
	query.bind(1, tableName);
	if (query.executeStep()) {
		SQLite::Statement query_update(*db, "UPDATE SQLITE_SEQUENCE SET seq=seq+1 WHERE name=?1");
		query_update.bind(1, tableName);
		query_update.exec();
		return (DB::Id)query.getColumn("seq") + 1;
	}
	else {
		SQLite::Statement query(*db, "INSERT INTO SQLITE_SEQUENCE (name, seq) VALUES (?1, 1)");
		query.bind(1, tableName);
		query.exec();
	}
	return 1;
}

DB::ChildAbstractMapper::ChildAbstractMapper(IMapper* parentMapper)
	: m_parentMapper(parentMapper)
{}

void DB::ChildAbstractMapper::insert(TransactionContext* ctx, IDomainObject* obj) {
	m_parentMapper->insert(ctx, obj);
	doInsert(ctx, obj);
}

void DB::ChildAbstractMapper::update(TransactionContext* ctx, IDomainObject* obj) {
	m_parentMapper->update(ctx, obj);
	doUpdate(ctx, obj);
}

void DB::ChildAbstractMapper::remove(TransactionContext* ctx, IDomainObject* obj) {
	m_parentMapper->remove(ctx, obj);
	doRemove(ctx, obj);
}

DB::IRepository* DB::ChildAbstractMapper::getRepository() {
	return m_parentMapper->getRepository();
}
