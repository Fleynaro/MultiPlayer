#pragma once
#include <DB/AbstractMapper.h>

namespace CE {
	class ProcessModule;
	class ProcessModuleManager;
};

namespace DB
{
	class ProcessModuleMapper : public AbstractMapper
	{
	public:
		ProcessModuleMapper(CE::ProcessModuleManager* manager);

		void loadAll();

		Id getNextId() override;

		CE::ProcessModuleManager* getManager();
	protected:
		IDomainObject* doLoad(Database* db, SQLite::Statement& query) override;

		void doInsert(TransactionContext* ctx, IDomainObject* obj) override;

		void doUpdate(TransactionContext* ctx, IDomainObject* obj) override;

		void doRemove(TransactionContext* ctx, IDomainObject* obj) override;

	private:
		void bind(SQLite::Statement& query, CE::ProcessModule& module);
	};
};