#include "FunctionTrigger.h"
#include "FunctionTriggerTableLog.h"

using namespace CE::Trigger::Function;

Trigger::Trigger(int id, const std::string& name, const std::string& desc)
	: AbstractTrigger(id, name, desc)
{
	m_compositeFilter = new Filter::ConditionFilter(Filter::Id::Condition_AND);
}

Trigger::~Trigger() {
	delete m_compositeFilter;
}

CE::Trigger::Type Trigger::getType() {
	return Type::FunctionTrigger;
}

bool Trigger::actionBefore(CE::Hook::DynHook* hook) {
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

void Trigger::actionAfter(CE::Hook::DynHook* hook) {
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

void Trigger::setStatCollector(CE::Stat::Function::Collector* collector) {
	m_statCollector = collector;
}

void Trigger::setNotExecute(bool toggle) {
	m_notExecute = toggle;
}

bool Trigger::isNotExecute() {
	return m_notExecute;
}

void Trigger::addFunction(CE::Function::Function* function) {
	m_functions.push_back(function);
}

void Trigger::start() {
	setActiveState(true);
	m_isActive = true;
}

void Trigger::stop() {
	setActiveState(false);
	m_isActive = false;
}

bool Trigger::isActive() {
	return m_isActive;
}

Filter::AbstractCompositeFilter* Trigger::getFilters() {
	return m_compositeFilter;
}

void Trigger::setTableLogEnable(bool toggle) {
	if (toggle) {
		m_tableLog = new TableLog(this);
	}
	else {
		delete m_tableLog;
		m_tableLog = nullptr;
	}
}

void Trigger::setActiveState(bool state) {
	for (auto it : m_functions) {
		if (!it->hasHook())
			continue;
		if (state) {
			it->getHook()->addActiveTrigger(this);
		}
		else {
			it->getHook()->removeActiveTrigger(this);
		}
	}
}

bool CE::Trigger::Function::callback_before(CE::Hook::DynHook* hook)
{
	auto func = (CE::Function::FunctionDefinition*)hook->getUserPtr();
	bool exectute = true;
	for (auto trigger : func->getHook()->getActiveTriggers()) {
		exectute &= trigger->actionBefore(hook);
	}

	auto funcName = func->getDeclaration().getName();
	auto& signature = func->getDeclaration().getSignature();
	auto hookMethod = hook->getMethod();

	auto value1 = hook->getArgumentValue<uint64_t>(1);
	auto value2 = hook->getArgumentValue<uint64_t>(2);
	auto value3 = hook->getArgumentValue<uint64_t>(3);
	auto value4 = hook->getArgumentValue<uint64_t>(4);
	auto value5 = hook->getArgumentValue<uint64_t>(5);
	auto value6 = hook->getArgumentValue<uint64_t>(6);
	auto value7 = hook->getArgumentValue<uint64_t>(7);

	auto int_value1 = hook->getArgumentValue<int>(1);
	auto int_value2 = hook->getArgumentValue<int>(2);
	auto int_value3 = hook->getArgumentValue<int>(3);
	auto int_value4 = hook->getArgumentValue<int>(4);
	auto int_value5 = hook->getArgumentValue<int>(5);
	auto int_value6 = hook->getArgumentValue<int>(6);
	auto int_value7 = hook->getArgumentValue<int>(7);

	auto xmm_value1 = hook->getXmmArgumentValue<float>(1);
	auto xmm_value2 = hook->getXmmArgumentValue<float>(2);
	auto xmm_value3 = hook->getXmmArgumentValue<float>(3);
	auto xmm_value4 = hook->getXmmArgumentValue<float>(4);
	auto xmm_value5 = hook->getXmmArgumentValue<float>(5);
	auto xmm_value6 = hook->getXmmArgumentValue<float>(6);
	auto xmm_value7 = hook->getXmmArgumentValue<float>(7);
	auto xmm_value8 = hook->getXmmArgumentValue<float>(8);

	return exectute;
}

void CE::Trigger::Function::callback_after(CE::Hook::DynHook* hook)
{
	auto func = (CE::Function::FunctionDefinition*)hook->getUserPtr();
	for (auto trigger : func->getHook()->getActiveTriggers()) {
		trigger->actionAfter(hook);
	}
	//hook->setReturnValue(11);

	auto retAddr = hook->getReturnAddress();
	auto retValue = hook->getReturnValue();
	auto xmm_retValue = hook->getXmmReturnValue<float>();

	int a = 5;
}
