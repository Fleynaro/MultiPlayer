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

		CE::TriggerManager* getManager();
	protected:
		IDomainObject* doLoad(Database* db, SQLite::Statement& query) override;

		void doInsert(Database* db, IDomainObject* obj) override;

		void doUpdate(Database* db, IDomainObject* obj) override;

		void doRemove(Database* db, IDomainObject* obj) override;

	private:
		void bind(SQLite::Statement& query, CE::Trigger::AbstractTrigger& tr);
	};
};