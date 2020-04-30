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
		void markAsNew(DomainObject* obj) override {
			m_insertedObjs.push_back(obj);
		}

		void markAsDirty(DomainObject* obj) override {
			m_updatedObjs.push_back(obj);
		}

		void markAsRemoved(DomainObject* obj) override {
			m_removedObjs.push_back(obj);
		}

		void commit() override {
			SQLite::Transaction transaction(db);

			for (auto obj : m_insertedObjs) {
				if(obj->m_mapper != nullptr)
					obj->m_mapper->insert(obj);
			}

			for (auto obj : m_updatedObjs) {
				if (obj->m_mapper != nullptr)
					obj->m_mapper->update(obj);
			}

			for (auto obj : m_removedObjs) {
				if (obj->m_mapper != nullptr)
					obj->m_mapper->remove(obj);
			}
		}
	private:
		std::list<DomainObject*> m_insertedObjs;
		std::list<DomainObject*> m_updatedObjs;
		std::list<DomainObject*> m_removedObjs;
	};
};