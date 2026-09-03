#pragma once
#include <DB/AbstractMapper.h>

namespace CE {
	class TriggerManager;

	namespace Trigger {
		class AbstractTrigger;
	}
};

namespace DB
{
	class FunctionTriggerMapper;

	class TriggerMapper : public AbstractMapper
	{
	public:
		FunctionTriggerMapper* m_functionTriggerMapper;

		TriggerMapper(IRepository* repository);

		void loadAll();

		Id getNextId() override;

		CE::TriggerManager* getManager();
	protected:
		IDomainObject* doLoad(Database* db, SQLite::Statement& query) override;

		void doInsert(TransactionContext* ctx, IDomainObject* obj) override;

		void doUpdate(TransactionContext* ctx, IDomainObject* obj) override;

		void doRemove(TransactionContext* ctx, IDomainObject* obj) override;

	private:
		void bind(SQLite::Statement& query, CE::Trigger::AbstractTrigger& tr);
	};
};