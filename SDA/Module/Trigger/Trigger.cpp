#include "Trigger.h"

CE::Trigger::Function::Hook* CE::Function::Function::createHook() {
	m_hook = new CE::Trigger::Function::Hook(this);
	return m_hook;
}

CE::Trigger::Function::Hook::Hook(CE::Function::Function* func)
{
	m_hook = CE::Hook::DynHook(func->getAddress(), &callback_before, &callback_after);
	m_hook.setUserPtr(func);
}