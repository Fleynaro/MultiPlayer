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

		TriggerManager(ProgramModule* module);

		Trigger::Function::Trigger* createFunctionTrigger(const std::string& name, const std::string& desc = "");

		void loadTriggers();

		Trigger::AbstractTrigger* getTriggerById(DB::Id id);

		Trigger::AbstractTrigger* getTriggerByName(const std::string& name);

	private:
		DB::TriggerMapper* m_triggerMapper;
	};
};