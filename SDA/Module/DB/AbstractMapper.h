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

	class IMapper
	{
	public:
		virtual void insert(Database* db, DomainObject* obj) = 0;
		virtual void update(Database* db, DomainObject* obj) = 0;
		virtual void remove(Database* db, DomainObject* obj) = 0;
	};

	class AbstractMapper : public IMapper
	{
	public:
		IRepository* m_repository;

		AbstractMapper(IRepository* repository = nullptr);

		void load(Database* db, Statement& query);

		void insert(Database* db, DomainObject* obj) override;

		void update(Database* db, DomainObject* obj) override;

		void remove(Database* db, DomainObject* obj) override;
		
		DomainObject* find(Id id);

		static void setNewId(Database* db, DomainObject* obj);
	protected:
		virtual DomainObject* doLoad(Database* db, Statement& query) = 0;
		virtual void doInsert(Database* db, DomainObject* obj) = 0;
		virtual void doUpdate(Database* db, DomainObject* obj) = 0;
		virtual void doRemove(Database* db, DomainObject* obj) = 0;
	};

	class ChildAbstractMapper : public IMapper
	{
	public:
		ChildAbstractMapper(IMapper* parentMapper)
			: m_parentMapper(parentMapper)
		{}

		virtual DomainObject* doLoad(Database* db, Statement& query) = 0;

		void insert(Database* db, DomainObject* obj);

		void update(Database* db, DomainObject* obj);

		void remove(Database* db, DomainObject* obj);

	protected:
		virtual void doInsert(Database* db, DomainObject* obj) = 0;
		virtual void doUpdate(Database* db, DomainObject* obj) = 0;
		virtual void doRemove(Database* db, DomainObject* obj) = 0;
		IMapper* m_parentMapper;
	};
};