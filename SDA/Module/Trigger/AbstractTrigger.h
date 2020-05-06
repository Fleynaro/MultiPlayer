#pragma once
#include <DB/DomainObject.h>
#include <Code/Code.h>

namespace CE::Trigger
{
	enum Type
	{
		FunctionTrigger
	};

	class AbstractTrigger : public DB::DomainObject
	{
	public:
		AbstractTrigger(const std::string& name, const std::string& desc = "");

		std::string getName();

		virtual Type getType() = 0;

		Desc& getDesc();
	private:
		Desc m_desc;
	};
};

namespace CE::Trigger
{
	class TriggerGroup : public DB::DomainObject
	{
	public:
		TriggerGroup(const std::string& name, const std::string& desc = "");

		std::string getName();

		void addTrigger(AbstractTrigger* trigger);

		std::list<AbstractTrigger*>& getTriggers();

		Desc& getDesc();
	private:
		Desc m_desc;
		std::list<AbstractTrigger*> m_triggers;
	};
};