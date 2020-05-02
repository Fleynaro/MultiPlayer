#include "Transaction.h"

using namespace SQLite;

DB::Transaction::Transaction(Database* db)
	: m_db(db)
{}

void DB::Transaction::markAsNew(DomainObject* obj) {
	m_insertedObjs.remove(obj);
	m_insertedObjs.push_back(obj);

	if (obj->m_mapper->m_repository != nullptr)
		obj->m_mapper->m_repository->onChangeBeforeCommit(obj, IRepository::Inserted);
}

void DB::Transaction::markAsDirty(DomainObject* obj) {
	m_updatedObjs.remove(obj);
	m_updatedObjs.push_back(obj);

	if (obj->m_mapper->m_repository != nullptr)
		obj->m_mapper->m_repository->onChangeBeforeCommit(obj, IRepository::Updated);
}

void DB::Transaction::markAsRemoved(DomainObject* obj) {
	m_removedObjs.remove(obj);
	m_removedObjs.push_back(obj);

	if (obj->m_mapper->m_repository != nullptr)
		obj->m_mapper->m_repository->onChangeBeforeCommit(obj, IRepository::Removed);
}

void DB::Transaction::commit() {
	SQLite::Transaction transaction(*m_db);

	//MYTODO: ид еще не присвоился объекту, а объект везде используется => не использовать в программе ID объектов

	for (auto obj : m_insertedObjs) {
		if (obj->m_mapper != nullptr) {
			obj->m_mapper->insert(m_db, obj);
			m_updatedObjs.remove(obj);
		}
	}

	for (auto obj : m_updatedObjs) {
		if (obj->m_mapper != nullptr)
			obj->m_mapper->update(m_db, obj);
	}

	for (auto obj : m_removedObjs) {
		if (obj->m_mapper != nullptr) {
			obj->m_mapper->remove(m_db, obj);
			delete obj;
		}
	}

	transaction.commit();
}
