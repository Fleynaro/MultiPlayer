#pragma once
#include "DomainObject.h"
#include <SQLiteCpp/SQLiteCpp.h>

namespace DB
{
	using namespace SQLite;

	struct TransactionContext
	{
		Id m_saveId;
		Database* m_db;
	};

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
		virtual void insert(TransactionContext* ctx, IDomainObject* obj) = 0;
		virtual void update(TransactionContext* ctx, IDomainObject* obj) = 0;
		virtual void remove(TransactionContext* ctx, IDomainObject* obj) = 0;
		virtual IRepository* getRepository() = 0;
	};

	class AbstractMapper : public IMapper
	{
	public:
		IRepository* m_repository;

		AbstractMapper(IRepository* repository = nullptr);

		virtual Id getNextId() = 0;

		void load(Database* db, Statement& query);

		void insert(TransactionContext* ctx, IDomainObject* obj) override;

		void update(TransactionContext* ctx, IDomainObject* obj) override;

		void remove(TransactionContext* ctx, IDomainObject* obj) override;

		IRepository* getRepository() override;
		
		IDomainObject* find(Id id);
	protected:
		virtual IDomainObject* doLoad(Database* db, Statement& query) = 0;
		virtual void doInsert(TransactionContext* ctx, IDomainObject* obj) = 0;
		virtual void doUpdate(TransactionContext* ctx, IDomainObject* obj) = 0;
		virtual void doRemove(TransactionContext* ctx, IDomainObject* obj) = 0;
	};

	class ChildAbstractMapper : public IMapper
	{
	public:
		ChildAbstractMapper(IMapper* parentMapper);

		virtual IDomainObject* doLoad(Database* db, Statement& query) = 0;

		void insert(TransactionContext* ctx, IDomainObject* obj);

		void update(TransactionContext* ctx, IDomainObject* obj);

		void remove(TransactionContext* ctx, IDomainObject* obj);

		IRepository* getRepository() override;
	protected:
		virtual void doInsert(TransactionContext* ctx, IDomainObject* obj) = 0;
		virtual void doUpdate(TransactionContext* ctx, IDomainObject* obj) = 0;
		virtual void doRemove(TransactionContext* ctx, IDomainObject* obj) = 0;
		IMapper* m_parentMapper;
	};

	Id GenerateNextId(Database* db, const std::string& tableName);
};