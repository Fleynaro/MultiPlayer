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

void DB::AbstractMapper::insert(Database* db, IDomainObject* obj) {
	if (m_repository != nullptr)
		m_repository->onChangeAfterCommit(obj, IRepository::Inserted);
	doInsert(db, obj);
}

void DB::AbstractMapper::update(Database* db, IDomainObject* obj) {
	if (m_repository != nullptr)
		m_repository->onChangeAfterCommit(obj, IRepository::Updated);
	doUpdate(db, obj);
}

void DB::AbstractMapper::remove(Database* db, IDomainObject* obj) {
	if (m_repository != nullptr)
		m_repository->onChangeAfterCommit(obj, IRepository::Removed);
	doRemove(db, obj);
}

DB::IRepository* DB::AbstractMapper::getRepository() {
	return m_repository;
}

DB::IDomainObject* DB::AbstractMapper::find(Id id) {
	return m_repository->find(id);
}

void DB::AbstractMapper::setNewId(Database* db, IDomainObject* obj) {
	auto id = (Id)db->getLastInsertRowid();
	if (!id) {
		return;
		//throw std::exception();
	}
	obj->setId(id);
}

DB::ChildAbstractMapper::ChildAbstractMapper(IMapper* parentMapper)
	: m_parentMapper(parentMapper)
{}

void DB::ChildAbstractMapper::insert(Database* db, IDomainObject* obj) {
	m_parentMapper->insert(db, obj);
	doInsert(db, obj);
}

void DB::ChildAbstractMapper::update(Database* db, IDomainObject* obj) {
	m_parentMapper->update(db, obj);
	doUpdate(db, obj);
}

void DB::ChildAbstractMapper::remove(Database* db, IDomainObject* obj) {
	m_parentMapper->remove(db, obj);
	doRemove(db, obj);
}

DB::IRepository* DB::ChildAbstractMapper::getRepository() {
	return m_parentMapper->getRepository();
}
