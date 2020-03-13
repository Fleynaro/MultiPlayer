#include "Trigger.h"

void CE::Function::FunctionDefinition::createHook() {
	if (m_hook != nullptr)
		delete m_hook;
	m_hook = new CE::Trigger::Function::Hook(this);
}

CE::Trigger::Function::Hook::Hook(CE::Function::FunctionDefinition* definition)
{
	m_hook = CE::Hook::DynHook(definition->getAddress(), &callback_before, &callback_after);
	m_hook.setUserPtr(definition);
}