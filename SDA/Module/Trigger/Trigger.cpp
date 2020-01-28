#include "Trigger.h"

CE::Trigger::Function::Hook* CE::Function::FunctionDefinition::createHook() {
	m_hook = new CE::Trigger::Function::Hook(this);
	return m_hook;
}

CE::Trigger::Function::Hook::Hook(CE::Function::FunctionDefinition* definition)
{
	m_hook = CE::Hook::DynHook(definition->getAddress(), &callback_before, &callback_after);
	m_hook.setUserPtr(definition);
}