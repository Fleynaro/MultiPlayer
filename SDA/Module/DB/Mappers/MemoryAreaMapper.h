#pragma once
#include <DB/AbstractMapper.h>
#include <Code/Symbol/MemoryArea/MemoryArea.h>

namespace CE {
	class MemoryAreaManager;
};

namespace DB
{
	class MemoryAreaMapper : public AbstractMapper
	{
	public:
		MemoryAreaMapper(IRepository* repository);

		void loadAll();

		Id getNextId() override;

		CE::MemoryAreaManager* getManager();
	protected:
		IDomainObject* doLoad(Database* db, SQLite::Statement& query) override;

		void loadSymbolsForAllMemAreas(Database* db);

		void saveSymbolsForMemArea(TransactionContext* ctx, CE::Symbol::MemoryArea* memoryArea);

		void doInsert(TransactionContext* ctx, IDomainObject* obj) override;

		void doUpdate(TransactionContext* ctx, IDomainObject* obj) override;

		void doRemove(TransactionContext* ctx, IDomainObject* obj) override;

	private:
		void bind(SQLite::Statement& query, CE::Symbol::MemoryArea& memoryArea);
	};
};