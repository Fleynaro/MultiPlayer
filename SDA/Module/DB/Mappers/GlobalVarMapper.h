#pragma once
#include <DB/AbstractMapper.h>
#include <Code/Variable/GlobalVar.h>

namespace CE {
	class GlobalVarManager;
};

namespace DB
{
	class GlobalVarMapper : public AbstractMapper
	{
	public:
		GlobalVarMapper(IRepository* repository);

		void loadAll();

		Id getNextId() override;

		CE::GlobalVarManager* getManager();
	protected:
		IDomainObject* doLoad(Database* db, SQLite::Statement& query) override;

		void doInsert(TransactionContext* ctx, IDomainObject* obj) override;

		void doUpdate(TransactionContext* ctx, IDomainObject* obj) override;

		void doRemove(TransactionContext* ctx, IDomainObject* obj) override;

	private:
		void bind(SQLite::Statement& query, CE::Variable::GlobalVar& gvar);
	};
};