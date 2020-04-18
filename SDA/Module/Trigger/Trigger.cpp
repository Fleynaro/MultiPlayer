#include "Trigger.h"
#include "TriggerTableLog.h"

using namespace CE::Trigger;

Function::Hook::Hook(CE::Function::FunctionDefinition* definition)
{
	m_hook = CE::Hook::DynHook(definition->getAddress(), &callback_before, &callback_after);
	m_hook.setMethod(new CE::Hook::Method::Method2<CE::Trigger::Function::TriggerState>(&m_hook));
	m_hook.setArgCount(max(4, (int)definition->getDeclaration().getSignature().getArgList().size()));
	m_hook.setUserPtr(definition);
}

bool Function::Trigger::actionBefore(CE::Hook::DynHook* hook) {
	bool filter;
	bool notExecute = false;
	if (filter = getFilters()->checkFilterBefore(hook)) {
		notExecute = m_notExecute;
		hook->getUserData<TriggerState>().m_beforeFilter = true;
	}

	if (m_tableLog != nullptr) {
		m_tableLog->addBeforeCallRow(hook, filter);
	}

	if (filter || m_sendStatAnyway) {
		if (m_statCollector != nullptr) {
			m_statCollector->addBeforeCallInfo(this, hook);
		}
	}
	return !notExecute;
}

void Function::Trigger::actionAfter(CE::Hook::DynHook* hook) {
	bool sendStat = hook->getUserData<TriggerState>().m_beforeFilter;
	bool filter;
	if (filter = getFilters()->checkFilterAfter(hook)) {
		sendStat = true;
	}

	if (m_tableLog != nullptr) {
		m_tableLog->addAfterCallRow(hook, filter);
	}

	if (sendStat || m_sendStatAnyway) {
		if (m_statCollector != nullptr) {
			m_statCollector->addAfterCallInfo(this, hook);
		}
	}
}

void Function::Trigger::setTableLogEnable(bool toggle) {
	if (toggle) {
		m_tableLog = new TableLog(this);
	}
	else {
		delete m_tableLog;
		m_tableLog = nullptr;
	}
}
