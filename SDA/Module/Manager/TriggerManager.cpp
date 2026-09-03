#include "TriggerManager.h"
#include <DB/Mappers/TriggerMapper.h>
#include <DB/Mappers/FunctionTriggerMapper.h>

using namespace CE;

TriggerManager::TriggerManager(ProgramModule* module)
	: AbstractItemManager(module)
{
	m_triggerMapper = new DB::TriggerMapper(this);
}

Trigger::Function::Trigger* TriggerManager::createFunctionTrigger(const std::string& name, const std::string& desc) {
	auto trigger = new Trigger::Function::Trigger(this, name, desc);
	trigger->setMapper(m_triggerMapper->m_functionTriggerMapper);
	trigger->setId(m_triggerMapper->getNextId());
	getProgramModule()->getTransaction()->markAsNew(trigger);
	return trigger;
}

void TriggerManager::loadTriggers()
{
	m_triggerMapper->loadAll();
}

Trigger::AbstractTrigger* TriggerManager::getTriggerByName(const std::string& name)
{
	Iterator it(this);
	while (it.hasNext()) {
		auto tr = it.next();
		if (tr->getName() == name) {
			return tr;
		}
	}
	return nullptr;
}

Trigger::AbstractTrigger* TriggerManager::getTriggerById(DB::Id id) {
	return (Trigger::AbstractTrigger*)find(id);
}
