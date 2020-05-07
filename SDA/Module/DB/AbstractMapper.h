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

		virtual void onLoaded(IDomainObject* obj) = 0;
		virtual void onChangeBeforeCommit(IDomainObject* obj, ChangeType type) = 0;
		virtual void onChangeAfterCommit(IDomainObject* obj, ChangeType type) = 0;
		virtual IDomainObject* find(Id id) = 0;
	};

	class IMapper
	{
	public:
		virtual void insert(Database* db, IDomainObject* obj) = 0;
		virtual void update(Database* db, IDomainObject* obj) = 0;
		virtual void remove(Database* db, IDomainObject* obj) = 0;
		virtual IRepository* getRepository() = 0;
	};

	class AbstractMapper : public IMapper
	{
	public:
		IRepository* m_repository;

		AbstractMapper(IRepository* repository = nullptr);

		virtual Id getNextId() = 0;

		void load(Database* db, Statement& query);

		void insert(Database* db, IDomainObject* obj) override;

		void update(Database* db, IDomainObject* obj) override;

		void remove(Database* db, IDomainObject* obj) override;

		IRepository* getRepository() override;
		
		IDomainObject* find(Id id);
	protected:
		virtual IDomainObject* doLoad(Database* db, Statement& query) = 0;
		virtual void doInsert(Database* db, IDomainObject* obj) = 0;
		virtual void doUpdate(Database* db, IDomainObject* obj) = 0;
		virtual void doRemove(Database* db, IDomainObject* obj) = 0;
	};

	class ChildAbstractMapper : public IMapper
	{
	public:
		ChildAbstractMapper(IMapper* parentMapper);

		virtual IDomainObject* doLoad(Database* db, Statement& query) = 0;

		void insert(Database* db, IDomainObject* obj);

		void update(Database* db, IDomainObject* obj);

		void remove(Database* db, IDomainObject* obj);

		IRepository* getRepository() override;
	protected:
		virtual void doInsert(Database* db, IDomainObject* obj) = 0;
		virtual void doUpdate(Database* db, IDomainObject* obj) = 0;
		virtual void doRemove(Database* db, IDomainObject* obj) = 0;
		IMapper* m_parentMapper;
	};

	Id GenerateNextId(Database* db, const std::string& tableName);
};