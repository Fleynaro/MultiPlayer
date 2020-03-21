#include "Trigger.h"

void CE::Function::FunctionDefinition::createHook() {
	m_hook = new CE::Trigger::Function::Hook(this);
}

CE::Trigger::Function::Hook::Hook(CE::Function::FunctionDefinition* definition)
{
	m_hook = CE::Hook::DynHook(definition->getAddress(), &callback_before, &callback_after);
	m_hook.setMethod(new CE::Hook::Method::Method2<CE::Trigger::Function::TriggerState>(&m_hook));
	m_hook.setArgCount(definition->getDeclaration().getSignature().getArgList().size());
	m_hook.setUserPtr(definition);
}