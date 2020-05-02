#pragma once
#include "AbstractMapper.h"

namespace DB
{
	//using namespace SQLite;

	class ITransaction
	{
	public:
		virtual void markAsNew(DomainObject* obj) = 0;
		virtual void markAsDirty(DomainObject* obj) = 0;
		virtual void markAsRemoved(DomainObject* obj) = 0;
		virtual void commit() = 0;
	};

	class Transaction : public ITransaction
	{
	public:
		Transaction(Database* db)
			: m_db(db)
		{}

		void markAsNew(DomainObject* obj) override {
			m_insertedObjs.insert(obj);

			if (obj->m_mapper->m_repository != nullptr)
				obj->m_mapper->m_repository->onChangeBeforeCommit(obj, IRepository::Inserted);
		}

		void markAsDirty(DomainObject* obj) override {
			m_updatedObjs.insert(obj);

			if (obj->m_mapper->m_repository != nullptr)
				obj->m_mapper->m_repository->onChangeBeforeCommit(obj, IRepository::Updated);
		}

		void markAsRemoved(DomainObject* obj) override {
			m_removedObjs.insert(obj);

			if (obj->m_mapper->m_repository != nullptr)
				obj->m_mapper->m_repository->onChangeBeforeCommit(obj, IRepository::Removed);
		}

		void commit() override {
			SQLite::Transaction transaction(*m_db);

			for (auto obj : m_insertedObjs) {
				if(obj->m_mapper != nullptr)
					obj->m_mapper->insert(m_db, obj);
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
	private:
		Database* m_db;
		std::set<DomainObject*> m_insertedObjs;
		std::set<DomainObject*> m_updatedObjs;
		std::set<DomainObject*> m_removedObjs;
	};
};