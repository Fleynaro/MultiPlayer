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

	class AbstractTrigger : public DB::DomainObject, public Description
	{
	public:
		AbstractTrigger(TriggerManager* triggerManager, const std::string& name, const std::string& comment = "");

		virtual Type getType() = 0;

		TriggerManager* getManager();
	private:
		TriggerManager* m_manager;
	};
};

namespace CE {
	class TriggerGroupManager;
};

namespace CE::Trigger
{
	class TriggerGroup : public DB::DomainObject, public Description
	{
	public:
		TriggerGroup(TriggerGroupManager* triggerGroupManager, const std::string& name, const std::string& comment = "");

		void addTrigger(AbstractTrigger* trigger);

		std::list<AbstractTrigger*>& getTriggers();

		TriggerGroupManager* getManager();
	private:
		std::list<AbstractTrigger*> m_triggers;
		TriggerGroupManager* m_manager;
	};
};