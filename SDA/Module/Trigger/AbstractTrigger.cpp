#include "AbstractTrigger.h"

using namespace CE;
using namespace CE::Trigger;

AbstractTrigger::AbstractTrigger(TriggerManager* triggerManager, const std::string& name, const std::string& desc)
	: m_manager(triggerManager), m_desc(name, desc)
{}

std::string AbstractTrigger::getName() {
	return m_desc.getName();
}

Desc& AbstractTrigger::getDesc() {
	return m_desc;
}

TriggerManager* AbstractTrigger::getManager() {
	return m_manager;
}

TriggerGroup::TriggerGroup(TriggerGroupManager* triggerGroupManager, const std::string& name, const std::string& desc)
	: m_manager(triggerGroupManager), m_desc(name, desc)
{}

std::string TriggerGroup::getName() {
	return m_desc.getName();
}

void TriggerGroup::addTrigger(AbstractTrigger* trigger) {
	m_triggers.push_back(trigger);
}

std::list<AbstractTrigger*>& TriggerGroup::getTriggers() {
	return m_triggers;
}

Desc& TriggerGroup::getDesc() {
	return m_desc;
}

TriggerGroupManager* TriggerGroup::getManager() {
	return m_manager;
}
