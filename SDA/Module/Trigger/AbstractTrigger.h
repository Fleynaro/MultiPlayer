#pragma once
#include <Code/Code.h>

namespace CE::Trigger
{
	enum Type
	{
		FunctionTrigger
	};

	class AbstractTrigger : public Desc
	{
	public:
		AbstractTrigger(int id, std::string name, std::string desc = "")
			: Desc(id, name, desc)
		{}

		virtual Type getType() = 0;
	};
};

namespace CE::Trigger
{
	class TriggerGroup
	{
	public:
		TriggerGroup(int id, std::string name, std::string desc = "")
			: m_desc(id, name, desc)
		{}

		void addTrigger(AbstractTrigger* trigger) {
			m_triggers.push_back(trigger);
		}

		std::list<AbstractTrigger*>& getTriggers() {
			return m_triggers;
		}

		Desc& getDesc() {
			return m_desc;
		}
	private:
		Desc m_desc;
		std::list<AbstractTrigger*> m_triggers;
	};
};