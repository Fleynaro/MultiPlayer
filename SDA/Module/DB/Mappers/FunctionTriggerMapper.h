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
		void doInsert(Database* db, IDomainObject* obj) override;

		void doUpdate(Database* db, IDomainObject* obj) override;

		void doRemove(Database* db, IDomainObject* obj) override;
	private:
		void saveFiltersForFuncTrigger(Database* db, CE::Trigger::Function::Trigger* trigger);

		void saveFiltersForFuncTriggerRec(Database* db, DB::Id trigger_id, int filter_idx, CE::Trigger::Function::Filter::AbstractFilter* filter);

		void loadFiltersForFuncTrigger(Database* db, CE::Trigger::Function::Trigger* trigger);

		void loadFiltersForFuncTriggerRec(SQLite::Statement& query, CE::Trigger::Function::Filter::AbstractCompositeFilter* compositeFilter);

		TriggerMapper* getParentMapper();
	};
};