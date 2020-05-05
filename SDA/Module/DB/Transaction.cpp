#include "Transaction.h"

using namespace SQLite;

DB::Transaction::Transaction(Database* db)
	: m_db(db)
{}

void DB::Transaction::markAsNew(IDomainObject* obj) {
	m_insertedObjs.remove(obj);
	m_insertedObjs.push_back(obj);

	if (obj->getMapper()->getRepository() != nullptr)
		obj->getMapper()->getRepository()->onChangeBeforeCommit(obj, IRepository::Inserted);
}

void DB::Transaction::markAsDirty(IDomainObject* obj) {
	m_updatedObjs.remove(obj);
	m_updatedObjs.push_back(obj);

	if (obj->getMapper()->getRepository() != nullptr)
		obj->getMapper()->getRepository()->onChangeBeforeCommit(obj, IRepository::Updated);
}

void DB::Transaction::markAsRemoved(IDomainObject* obj) {
	m_removedObjs.remove(obj);
	m_removedObjs.push_back(obj);

	if (obj->getMapper()->getRepository() != nullptr)
		obj->getMapper()->getRepository()->onChangeBeforeCommit(obj, IRepository::Removed);
}

void DB::Transaction::commit() {
	SQLite::Transaction transaction(*m_db);

	//MYTODO: ид еще не присвоился объекту, а объект везде используется => не использовать в программе ID объектов

	for (auto obj : m_insertedObjs) {
		if (obj->getMapper() != nullptr) {
			if (!obj->isCommited()) {
				obj->getMapper()->insert(m_db, obj);
			}
			m_updatedObjs.remove(obj);
		}
	}

	for (auto obj : m_updatedObjs) {
		if (obj->getMapper() != nullptr)
			obj->getMapper()->update(m_db, obj);
	}

	for (auto obj : m_removedObjs) {
		if (obj->getMapper() != nullptr) {
			obj->getMapper()->remove(m_db, obj);
			delete obj;
		}
	}

	transaction.commit();
}
