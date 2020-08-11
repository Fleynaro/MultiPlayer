#pragma once
#include <Code/Function/Function.h>

namespace CE {
	class FunctionManager;
};

namespace DB
{
	class FunctionDefMapper : public AbstractMapper
	{
	public:
		FunctionDefMapper(CE::FunctionManager* repository);

		void loadAll();

		Id getNextId() override;

		CE::FunctionManager* getManager();
	protected:
		IDomainObject* doLoad(Database* db, SQLite::Statement& query) override;

		void loadFunctionRanges(Database* db, CE::Function::Function& definition);

		void saveFunctionRanges(TransactionContext* ctx, CE::Function::Function& definition);

		void doInsert(TransactionContext* ctx, IDomainObject* obj) override;

		void doUpdate(TransactionContext* ctx, IDomainObject* obj) override;

		void doRemove(TransactionContext* ctx, IDomainObject* obj) override;

	private:
		void bind(SQLite::Statement& query, CE::Function::Function& def);
	};
};