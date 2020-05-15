#pragma once
#include "TriggerMapper.h"

namespace CE {
	class TriggerManager;

	namespace Trigger::Function {
		class Trigger;

		namespace Filter {
			class AbstractFilter;
			class AbstractCompositeFilter;
		};
	};
};

namespace DB
{
	class FunctionTriggerMapper : public ChildAbstractMapper
	{
	public:
		FunctionTriggerMapper(TriggerMapper* parentMapper);

		IDomainObject* doLoad(Database* db, SQLite::Statement& query) override;
	protected:
		void doInsert(TransactionContext* ctx, IDomainObject* obj) override;

		void doUpdate(TransactionContext* ctx, IDomainObject* obj) override;

		void doRemove(TransactionContext* ctx, IDomainObject* obj) override;
	private:
		void saveFiltersForFuncTrigger(TransactionContext* ctx, CE::Trigger::Function::Trigger* trigger);

		void saveFiltersForFuncTriggerRec(TransactionContext* ctx, DB::Id trigger_id, int filter_idx, CE::Trigger::Function::Filter::AbstractFilter* filter);

		void loadFiltersForFuncTrigger(Database* db, CE::Trigger::Function::Trigger* trigger);

		void loadFiltersForFuncTriggerRec(SQLite::Statement& query, CE::Trigger::Function::Filter::AbstractCompositeFilter* compositeFilter);

		TriggerMapper* getParentMapper();
	};
};