#include "TriggerManager.h"
#include <DB/Mappers/TriggerMapper.h>
#include <DB/Mappers/FunctionTriggerMapper.h>

using namespace CE;

TriggerManager::TriggerManager(Project* module)
	: AbstractItemManager(module)
{
	m_triggerMapper = new DB::TriggerMapper(this);
}

Trigger::Function::Trigger* TriggerManager::createFunctionTrigger(const std::string& name, const std::string& desc, bool generateId) {
	auto trigger = new Trigger::Function::Trigger(this, name, desc);
	trigger->setMapper(m_triggerMapper->m_functionTriggerMapper);
	if(generateId)
		trigger->setId(m_triggerMapper->getNextId());
	return trigger;
}

void TriggerManager::loadTriggers()
{
	m_triggerMapper->loadAll();
}

Trigger::AbstractTrigger* TriggerManager::findTriggerByName(const std::string& name)
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

Trigger::AbstractTrigger* TriggerManager::findTriggerById(DB::Id id) {
	return (Trigger::AbstractTrigger*)find(id);
}
