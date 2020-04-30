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
			Loaded,
			Inserted,
			Updated,
			Removed
		};

		virtual void onChange(DomainObject* obj, ChangeType type) = 0;
		virtual DomainObject* find(Id id) = 0;
	};

	class AbstractMapper
	{
	public:
		AbstractMapper(Database* db, IRepository* repository = nullptr)
			: m_db(db), m_repository(repository)
		{}

		DomainObject* load(Statement& query) {
			while (query.executeStep())
			{
				auto obj = doLoad(query);
				if (obj != nullptr) {
					if (m_repository != nullptr)
						m_repository->onChange(obj, IRepository::Loaded);
				}
			}
		}

		void insert(DomainObject* obj) {
			if(m_repository != nullptr)
				m_repository->onChange(obj, IRepository::Inserted);
			doInsert(obj);
		}

		void update(DomainObject* obj) {
			if (m_repository != nullptr)
				m_repository->onChange(obj, IRepository::Updated);
			doUpdate(obj);
		}

		void remove(DomainObject* obj) {
			if (m_repository != nullptr)
				m_repository->onChange(obj, IRepository::Removed);
			doRemove(obj);
		}
		
		DomainObject* find(Id id) {
			return m_repository->find(id);
		}
	protected:
		Database* m_db;
		IRepository* m_repository;

		virtual DomainObject* doLoad(Statement& query) = 0;
		virtual void doInsert(DomainObject* obj) = 0;
		virtual void doUpdate(DomainObject* obj) = 0;
		virtual void doRemove(DomainObject* obj) = 0;

		void setNewId(DomainObject* obj) {
			auto id = (Id)m_db->getLastInsertRowid();
			if (!id) {
				throw std::exception();
			}
			obj->setId(id);
		}
	};
};