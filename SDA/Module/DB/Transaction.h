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
		Transaction(Database* db);

		void markAsNew(DomainObject* obj) override;

		void markAsDirty(DomainObject* obj) override;

		void markAsRemoved(DomainObject* obj) override;

		void commit() override;
	private:
		Database* m_db;
		std::list<DomainObject*> m_insertedObjs;
		std::list<DomainObject*> m_updatedObjs;
		std::list<DomainObject*> m_removedObjs;
	};
};