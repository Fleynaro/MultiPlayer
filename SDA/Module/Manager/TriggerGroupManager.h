#pragma once
#include "AbstractManager.h"
#include <Trigger/FunctionTrigger.h>

namespace DB {
	class TriggerGroupMapper;
};

namespace CE
{
	class TriggerGroupManager : public AbstractItemManager
	{
	public:
		using Iterator = AbstractIterator<Trigger::TriggerGroup>;

		TriggerGroupManager(Project* module);

		void loadTriggerGroups();

		Trigger::TriggerGroup* createTriggerGroup(const std::string& name, const std::string& desc = "", bool generateId = true);

		Trigger::TriggerGroup* findTriggerGroupById(DB::Id id);

		Trigger::TriggerGroup* findTriggerGroupByName(const std::string& name);

	private:
		DB::TriggerGroupMapper* m_triggerGroupMapper;
	};
};