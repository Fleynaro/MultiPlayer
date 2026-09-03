#include "AbstractTrigger.h"

using namespace CE;
using namespace CE::Trigger;

AbstractTrigger::AbstractTrigger(TriggerManager* triggerManager, const std::string& name, const std::string& comment)
	: m_manager(triggerManager), Descrtiption(name, comment)
{}


TriggerManager* AbstractTrigger::getManager() {
	return m_manager;
}

TriggerGroup::TriggerGroup(TriggerGroupManager* triggerGroupManager, const std::string& name, const std::string& comment)
	: m_manager(triggerGroupManager), Descrtiption(name, comment)
{}

void TriggerGroup::addTrigger(AbstractTrigger* trigger) {
	m_triggers.push_back(trigger);
}

std::list<AbstractTrigger*>& TriggerGroup::getTriggers() {
	return m_triggers;
}
TriggerGroupManager* TriggerGroup::getManager() {
	return m_manager;
}
