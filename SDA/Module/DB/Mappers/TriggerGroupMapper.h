#pragma once
#include <DB/AbstractMapper.h>

namespace CE {
	class TriggerGroupManager;

	namespace Trigger {
		class TriggerGroup;
	}
};

namespace DB
{
	class TriggerGroupMapper : public AbstractMapper
	{
	public:
		TriggerGroupMapper(IRepository* repository);

		void loadAll();

		Id getNextId() override;

		CE::TriggerGroupManager* getManager();
	protected:
		IDomainObject* doLoad(Database* db, SQLite::Statement& query) override;

		void saveTriggersForGroup(TransactionContext* ctx, CE::Trigger::TriggerGroup* group);

		void loadTriggersForGroup(Database* db, CE::Trigger::TriggerGroup* group);

		void doInsert(TransactionContext* ctx, IDomainObject* obj) override;

		void doUpdate(TransactionContext* ctx, IDomainObject* obj) override;

		void doRemove(TransactionContext* ctx, IDomainObject* obj) override;

	private:
		void bind(SQLite::Statement& query, CE::Trigger::TriggerGroup& group);
	};
};