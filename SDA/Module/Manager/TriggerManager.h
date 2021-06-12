#pragma once
#include "AbstractManager.h"
#include <Trigger/FunctionTrigger.h>

namespace DB {
	class TriggerMapper;
};

namespace CE
{
	class TriggerManager : public AbstractItemManager
	{
	public:
		using Iterator = AbstractIterator<Trigger::AbstractTrigger>;

		TriggerManager(Project* module);

		Trigger::Function::Trigger* createFunctionTrigger(const std::string& name, const std::string& desc = "", bool generateId = true);

		void loadTriggers();

		Trigger::AbstractTrigger* findTriggerById(DB::Id id);

		Trigger::AbstractTrigger* findTriggerByName(const std::string& name);

	private:
		DB::TriggerMapper* m_triggerMapper;
	};
};