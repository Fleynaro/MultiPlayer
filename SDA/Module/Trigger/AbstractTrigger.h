#pragma once
#include <DB/DomainObject.h>
#include <Code/Code.h>

namespace CE {
	class TriggerManager;
};

namespace CE::Trigger
{
	enum Type
	{
		FunctionTrigger
	};

	class AbstractTrigger : public DB::DomainObject
	{
	public:
		AbstractTrigger(TriggerManager* triggerManager, const std::string& name, const std::string& desc = "");

		std::string getName();

		virtual Type getType() = 0;

		Desc& getDesc();

		TriggerManager* getManager();
	private:
		Desc m_desc;
		TriggerManager* m_manager;
	};
};

namespace CE {
	class TriggerGroupManager;
};

namespace CE::Trigger
{
	class TriggerGroup : public DB::DomainObject
	{
	public:
		TriggerGroup(TriggerGroupManager* triggerGroupManager, const std::string& name, const std::string& desc = "");

		std::string getName();

		void addTrigger(AbstractTrigger* trigger);

		std::list<AbstractTrigger*>& getTriggers();

		Desc& getDesc();

		TriggerGroupManager* getManager();
	private:
		Desc m_desc;
		std::list<AbstractTrigger*> m_triggers;
		TriggerGroupManager* m_manager;
	};
};