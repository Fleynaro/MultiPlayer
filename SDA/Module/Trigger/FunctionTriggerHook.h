#pragma once
#include <Code/Code.h>
#include <DynHook/DynHook.h>

namespace CE::Trigger::Function
{
	class Trigger;
	class Hook
	{
	public:
		Hook(CE::Function::FunctionDefinition* definition);

		std::list<Trigger*>& getActiveTriggers();

		CE::Hook::DynHook* getDynHook();

		CE::Function::FunctionDefinition* getFunctionDef();

		void addActiveTrigger(Trigger* trigger);

		void removeActiveTrigger(Trigger* trigger);
	private:
		CE::Hook::DynHook m_hook;
		std::list<Trigger*> m_activeTriggers;
	};
};