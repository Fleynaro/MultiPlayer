#pragma once
#include "DomainObject.h"
#include <SQLiteCpp/SQLiteCpp.h>

namespace DB
{
	using namespace SQLite;

	class IRepository
	{
	public:
		enum ChangeType {
			Inserted,
			Updated,
			Removed
		};

		virtual void onLoaded(DomainObject* obj) = 0;
		virtual void onChangeBeforeCommit(DomainObject* obj, ChangeType type) = 0;
		virtual void onChangeAfterCommit(DomainObject* obj, ChangeType type) = 0;
		virtual DomainObject* find(Id id) = 0;
	};

	class AbstractMapper
	{
	public:
		IRepository* m_repository;

		AbstractMapper(IRepository* repository = nullptr)
			: m_repository(repository)
		{}

		DomainObject* load(Database* db, Statement& query) {
			while (query.executeStep())
			{
				auto obj = doLoad(db, query);
				if (obj != nullptr) {
					if (m_repository != nullptr)
						m_repository->onLoaded(obj);
					obj->m_mapper = this;
				}
			}
		}

		void insert(Database* db, DomainObject* obj) {
			if(m_repository != nullptr)
				m_repository->onChangeAfterCommit(obj, IRepository::Inserted);
			doInsert(db, obj);
			
			auto id = (Id)db->getLastInsertRowid();
			if (!id) {
				return;
				//throw std::exception();
			}
			obj->setId(id);
		}

		void update(Database* db, DomainObject* obj) {
			if (m_repository != nullptr)
				m_repository->onChangeAfterCommit(obj, IRepository::Updated);
			doUpdate(db, obj);
		}

		void remove(Database* db, DomainObject* obj) {
			if (m_repository != nullptr)
				m_repository->onChangeAfterCommit(obj, IRepository::Removed);
			doRemove(db, obj);
		}
		
		DomainObject* find(Id id) {
			return m_repository->find(id);
		}
	protected:
		virtual DomainObject* doLoad(Database* db, Statement& query) = 0;
		virtual void doInsert(Database* db, DomainObject* obj) = 0;
		virtual void doUpdate(Database* db, DomainObject* obj) = 0;
		virtual void doRemove(Database* db, DomainObject* obj) = 0;
	};
};