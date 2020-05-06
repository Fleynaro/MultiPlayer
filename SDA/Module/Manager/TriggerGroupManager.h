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

		TriggerGroupManager(ProgramModule* module);

		void loadTriggerGroups();

		Trigger::TriggerGroup* createTriggerGroup(const std::string& name, const std::string& desc = "");

		Trigger::TriggerGroup* getTriggerGroupById(DB::Id id);

		Trigger::TriggerGroup* getTriggerGroupByName(const std::string& name);

	private:
		DB::TriggerGroupMapper* m_triggerGroupMapper;
	};
};