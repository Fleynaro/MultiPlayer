#pragma once
#include <DB/AbstractMapper.h>
#include <Code/Symbol/MemoryArea/MemoryArea.h>

namespace CE {
	class SymbolTableManager;
};

namespace DB
{
	class SymbolTableMapper : public AbstractMapper
	{
	public:
		SymbolTableMapper(IRepository* repository);

		void loadAll();

		Id getNextId() override;

		CE::SymbolTableManager* getManager();
	protected:
		IDomainObject* doLoad(Database* db, SQLite::Statement& query) override;

		void loadSymbolsForAllSymTables(Database* db);

		void saveSymbolsForSymTable(TransactionContext* ctx, CE::Symbol::SymbolTable* memoryArea);

		void doInsert(TransactionContext* ctx, IDomainObject* obj) override;

		void doUpdate(TransactionContext* ctx, IDomainObject* obj) override;

		void doRemove(TransactionContext* ctx, IDomainObject* obj) override;

	private:
		void bind(SQLite::Statement& query, CE::Symbol::SymbolTable& memoryArea);
	};
};