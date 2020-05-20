#include "FunctionTriggerHook.h"
#include "FunctionTrigger.h"

using namespace CE::Trigger::Function;

Hook::Hook(CE::Function::FunctionDefinition* definition)
{
	m_hook = CE::Hook::DynHook(definition->getAddress(), &callback_before, &callback_after);
	m_hook.setMethod(new CE::Hook::Method::Method2<TriggerState>(&m_hook));
	m_hook.setArgCount(max(4, (int)definition->getDeclaration().getSignature()->getArguments().size()));
	m_hook.setUserPtr(definition);
}

std::list<Trigger*>& Hook::getActiveTriggers() {
	return m_activeTriggers;
}

CE::Hook::DynHook* Hook::getDynHook() {
	return &m_hook;
}

CE::Function::FunctionDefinition* Hook::getFunctionDef() {
	return static_cast<CE::Function::FunctionDefinition*>(getDynHook()->getUserPtr());
}

void Hook::addActiveTrigger(Trigger* trigger) {
	//mutex
	if (m_activeTriggers.size() == 0) {
		m_hook.enable();
	}
	m_activeTriggers.push_back(trigger);
}

void Hook::removeActiveTrigger(Trigger* trigger) {
	//mutex
	m_activeTriggers.remove(trigger);

	if (m_activeTriggers.size() == 0) {
		m_hook.disable();
	}
}
